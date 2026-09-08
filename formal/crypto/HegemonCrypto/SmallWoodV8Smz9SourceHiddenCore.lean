import HegemonCrypto.SmallWoodV8Smz9HiddenLifetime
import HegemonCrypto.SmallWoodV8Smz9SourceLifetime
import HegemonCrypto.SmallWoodV8Smz9MixedFinalAccounting

namespace HegemonCrypto.SmallWood.V8Smz9SourceHiddenEmbedding

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9CurrentPrivacyComposition V8Smz9EagerPrivacy V8Smz9EagerOracleGame
open V8Smz9HonestRequestSchedule V8Smz9HonestFinalGame V8Smz9HonestHybrid
open V8Smz9DynamicRequest V8Smz9DynamicTransport V8Smz9PostFinalProgram V8Smz9PostFinalPhysical
open V8Smz9MixedFinalOperational V8Smz9BytePrefix
open V8Smz9SourceByteProgram V8Smz9RuntimeDistribution
open V8Smz9MeasuredSameOracleAdjacent
open V8Smz9HonestWholeViewGames (GameState)
open V8Smz9MixedMaskCompiler (MixedProgram)
open scoped Classical BigOperators

noncomputable section
set_option maxHeartbeats 600000
set_option maxRecDepth 10000
set_option Elab.async false

variable {bound : Nat} {Work : Type} [Fintype Work]


theorem run_budget_transport (world : Bool) {left right requests : Nat}
    (budget : left = right) (program : V8Smz9HiddenLifetime.Lifetime bound Work left requests)
    (oracle : FullOracle bound) (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9HiddenLifetime.runLifetime world (budget ▸ program) oracle state =
      V8Smz9HiddenLifetime.runLifetime world program oracle state := by
  cases budget
  rfl


theorem run_uniform_random (world : Bool) (A : Type) [Fintype A] [Nonempty A]
    {queries requests : Nat} (next : A → V8Smz9HiddenLifetime.Lifetime bound Work queries requests)
    (oracle : FullOracle bound) (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9HiddenLifetime.runLifetime world (.random (uniformCoins A) next) oracle state =
      uniformAverage (fun coin : A => V8Smz9HiddenLifetime.runLifetime world (next coin) oracle state) := rfl


theorem run_nonleaf (world : Bool) {queries requests reads : Nat} {Result : Type}
    (program : NonleafProgram (OtherRawInput bound) Result) (counted : NonleafProgram.readCount program ≤ reads)
    (next : Result → V8Smz9HiddenLifetime.Lifetime bound Work queries requests)
    (oracle : FullOracle bound) (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9HiddenLifetime.runLifetime world (.nonleaf reads program counted next) oracle state =
      V8Smz9HiddenLifetime.runLifetime world
        (next (NonleafProgram.interpret (fun input => oracle (Sum.inr input)) program)) oracle state :=
  V8Smz9HiddenLifetime.nonleaf_execution world reads program counted next oracle state


theorem run_write (world : Bool) {queries requests : Nat} (input : FullRawInput bound)
    (answer : DigestRegister) (next : V8Smz9HiddenLifetime.Lifetime bound Work queries requests)
    (oracle : FullOracle bound) (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9HiddenLifetime.runLifetime world (.write input answer next) oracle state =
      V8Smz9HiddenLifetime.runLifetime world next (Function.update oracle input answer) state := rfl


def finalByteStage (largeEnough : 37434 ≤ bound)
    (request : V8Smz9SourceLifetime.SourceRequestData bound)
    (labels : LeafIndex → DigestRegister) (stage : PrefinalResult)
    (response : DecsFullCoefficients Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (digest : DigestRegister) : V8Smz9HiddenLifetime.SourceByteStage bound where
  largeEnough := largeEnough
  statement := request.statement
  publicValues := request.publicValues
  batching := sourceDecodedPiopGamma request.retainedRows stage.piopGamma
  gamma := sourceDecodedDecsGamma stage.decsGamma
  response := response
  transcript := transcript
  digest := digest
  pending := retainedPending stage
  salt := request.salt
  labels := labels
  tree := stage.tree
  witness := request.witness
  domain := request.domain


def hiddenRequestShape (A B C E : Type) [Fintype A] [Nonempty A]
    [Fintype B] [Nonempty B] [Fintype C] [Nonempty C] [Fintype E] [Nonempty E]
    {Result : Type} (reads : Nat)
    (prelude : A → B → NonleafProgram (OtherRawInput bound) Result)
    (counted : ∀ first second, NonleafProgram.readCount (prelude first second) ≤ reads)
    (key : Result → C → FullRawInput bound) (answer : E → DigestRegister)
    (stage : A → B → Result → C → E → V8Smz9HiddenLifetime.SourceByteStage bound)
    {queries requests : Nat}
    (next : ByteResult → V8Smz9HiddenLifetime.Lifetime bound Work queries requests) :
    V8Smz9HiddenLifetime.Lifetime bound Work
      (reads + ((V8Smz9HiddenLifetime.byteCallCost + queries) + 1)) (requests + 1) :=
  .random (uniformCoins A) fun first =>
    .random (uniformCoins B) fun second =>
      .nonleaf reads (prelude first second) (counted first second) fun retained =>
        .random (uniformCoins C) fun third =>
          .random (uniformCoins E) fun fourth =>
            .write (key retained third) (answer fourth)
              (.byteCall (stage first second retained third fourth) next)

theorem hidden_request_shape_executes (world : Bool) (A B C E : Type) [Fintype A] [Nonempty A]
    [Fintype B] [Nonempty B] [Fintype C] [Nonempty C] [Fintype E] [Nonempty E]
    {Result : Type} (reads : Nat)
    (prelude : A → B → NonleafProgram (OtherRawInput bound) Result)
    (counted : ∀ first second, NonleafProgram.readCount (prelude first second) ≤ reads)
    (key : Result → C → FullRawInput bound) (answer : E → DigestRegister)
    (stage : A → B → Result → C → E → V8Smz9HiddenLifetime.SourceByteStage bound)
    {queries requests : Nat}
    (next : ByteResult → V8Smz9HiddenLifetime.Lifetime bound Work queries requests)
    (oracle : FullOracle bound) (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9HiddenLifetime.runLifetime world
      (hiddenRequestShape A B C E reads prelude counted key answer stage next) oracle state =
      uniformAverage (fun first : A => uniformAverage (fun second : B =>
        let retained := NonleafProgram.interpret (fun input => oracle (Sum.inr input)) (prelude first second)
        uniformAverage (fun third : C => uniformAverage (fun fourth : E =>
          V8Smz9HiddenLifetime.runLifetime world (.byteCall (stage first second retained third fourth) next)
            (Function.update oracle (key retained third) (answer fourth)) state)))) := by
  simp only [hiddenRequestShape, run_uniform_random, run_nonleaf, run_write]


/-- The selected final event is represented as genuine fresh T and digest
coins followed by a charged persistent write at the exact source final key. -/
def hiddenRequest (largeEnough : 37434 ≤ bound)
    (request : V8Smz9SourceLifetime.SourceRequestData bound)
    {queries requests : Nat}
    (next : ByteResult → V8Smz9HiddenLifetime.Lifetime bound Work queries requests) :
    V8Smz9HiddenLifetime.Lifetime bound Work (16790291 + queries) (requests + 1) := by
  let built : V8Smz9HiddenLifetime.Lifetime bound Work
      (8401585 + ((V8Smz9HiddenLifetime.byteCallCost + queries) + 1)) (requests + 1) :=
    hiddenRequestShape (LeafIndex → DigestRegister) (DecsFullCoefficients Goldilocks)
      (PiopCoefficients Goldilocks) DigestRegister 8401585
      (fun labels response => sourcePrefinal bound (by omega) request.statementBinding request.bindingFits
        request.salt labels response request.retainedRows request.rowBound)
      (fun labels response => source_fixed_prefinal_read_bound bound (by omega)
        request.statementBinding request.bindingFits request.salt labels response request.retainedRows request.rowBound)
      (fun stage transcript => sourceFinalKey bound (by omega) (sourceDigestPrefix stage.hashFpp) transcript)
      id (fun labels response stage => finalByteStage largeEnough request labels stage response) next
  have budget : 8401585 + ((V8Smz9HiddenLifetime.byteCallCost + queries) + 1) =
      16790291 + queries := by
    unfold V8Smz9HiddenLifetime.byteCallCost
    omega
  exact budget ▸ built


attribute [local irreducible] uniformAverage V8Smz9HiddenLifetime.runLifetime
  V8Smz9MixedMaskCompiler.run V8Smz9HonestWholeViewGames.run sourcePrefinal

theorem hidden_request_executes_retained_prefix (world : Bool) (largeEnough : 37434 ≤ bound)
    (request : V8Smz9SourceLifetime.SourceRequestData bound) {queries requests : Nat}
    (next : ByteResult → V8Smz9HiddenLifetime.Lifetime bound Work queries requests)
    (oracle : FullOracle bound) (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9HiddenLifetime.runLifetime world (hiddenRequest largeEnough request next) oracle state =
      uniformAverage (fun labels : LeafIndex → DigestRegister =>
        uniformAverage (fun response : DecsFullCoefficients Goldilocks =>
          let stage := sourcePublicPrefinal bound (by omega) request.statementBinding request.bindingFits
            request.salt request.retainedRows request.rowBound (fun input => oracle (Sum.inr input)) labels response
          uniformAverage (fun transcript : PiopCoefficients Goldilocks =>
            uniformAverage (fun digest : DigestRegister =>
              V8Smz9HiddenLifetime.runLifetime world
                (.byteCall (finalByteStage largeEnough request labels stage response transcript digest) next)
                (Function.update oracle
                  (sourceFinalKey bound (by omega) (sourceDigestPrefix stage.hashFpp) transcript) digest) state)))) := by
  unfold hiddenRequest
  rw [run_budget_transport, hidden_request_shape_executes]
  rfl


/-- The source AST, including every adversarial branch, is mapped once
before sampling the initial random oracle. Neither an oracle nor a state is
an input to the compiler. -/
def compileHidden (largeEnough : 37434 ≤ bound) : {queries requests : Nat} →
    V8Smz9SourceLifetime.Lifetime bound Work queries requests →
      V8Smz9HiddenLifetime.Lifetime bound Work queries requests
  | _, _, .finish event => .finish event
  | _, _, .gate operation next => .gate operation (compileHidden largeEnough next)
  | _, _, .quantumQuery next => .quantumQuery (compileHidden largeEnough next)
  | _, _, .honestRead input next => .honestRead input (fun digest => compileHidden largeEnough (next digest))
  | _, _, .instrument operation next => .instrument operation (fun result => compileHidden largeEnough (next result))
  | _, _, .random source next => .random source (fun coins => compileHidden largeEnough (next coins))
  | _, _, .sourceRequest request next => hiddenRequest largeEnough request (fun bytes => compileHidden largeEnough (next bytes))


end
end HegemonCrypto.SmallWood.V8Smz9SourceHiddenEmbedding
