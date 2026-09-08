import HegemonCrypto.SmallWoodV8Smz9SourcePublicErasure
import HegemonCrypto.SmallWoodV8Smz9HiddenPublicSimulator
import HegemonCrypto.SmallWoodV8Smz9SourceHiddenCore

/-! The complete source simulator consumes public requests and public control
flow only. Its exact erasure factorization is derived from the actual source
request factory; neither witness selection nor an endpoint equality is an input. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourcePublicSimulator

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9EagerOracleGame V8Smz9HonestWholeViewGames V8Smz9HonestFinalGame
open V8Smz9HonestRequestSchedule V8Smz9HonestHybrid V8Smz9DynamicRequest
open V8Smz9DynamicTransport V8Smz9BytePrefix V8Smz9MixedFinalOperational
open V8Smz9EagerPrivacy
open V8Smz9SourceHiddenEmbedding V8Smz9HiddenPublicErasure
open V8Smz9SourcePublicErasure
open scoped Classical

noncomputable section
set_option maxHeartbeats 600000
set_option maxRecDepth 10000
set_option Elab.async false

variable {bound : Nat} {Work : Type} [Fintype Work]

def publicFinalByteStage (largeEnough : 37434 ≤ bound) (request : PublicRequestData bound)
    (labels : LeafIndex → DigestRegister) (stage : PrefinalResult)
    (response : DecsFullCoefficients Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (digest : DigestRegister) : PublicByteStage bound where
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

theorem public_final_stage_projection (largeEnough : 37434 ≤ bound)
    (request : V8Smz9SourceLifetime.SourceRequestData bound)
    (labels : LeafIndex → DigestRegister) (stage : PrefinalResult)
    (response : DecsFullCoefficients Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (digest : DigestRegister) :
    publicStage (finalByteStage largeEnough request labels stage response transcript digest) =
      publicFinalByteStage largeEnough (publicRequest request) labels stage response transcript digest := rfl

def publicRequestShape (A B C E : Type) [Fintype A] [Nonempty A]
    [Fintype B] [Nonempty B] [Fintype C] [Nonempty C] [Fintype E] [Nonempty E]
    {Result : Type} (reads : Nat)
    (prelude : A → B → NonleafProgram (OtherRawInput bound) Result)
    (counted : ∀ first second, NonleafProgram.readCount (prelude first second) ≤ reads)
    (key : Result → C → FullRawInput bound) (answer : E → DigestRegister)
    (stage : A → B → Result → C → E → PublicByteStage bound)
    {queries requests : Nat}
    (next : ByteResult → V8Smz9HiddenPublicSimulator.PublicLifetime bound Work queries requests) :
    V8Smz9HiddenPublicSimulator.PublicLifetime bound Work
      (reads + ((V8Smz9HiddenLifetime.byteCallCost + queries) + 1)) (requests + 1) :=
  .random (uniformCoins A) fun first =>
    .random (uniformCoins B) fun second =>
      .nonleaf reads (prelude first second) (counted first second) fun retained =>
        .random (uniformCoins C) fun third =>
          .random (uniformCoins E) fun fourth =>
            .write (key retained third) (answer fourth)
              (.byteCall (stage first second retained third fourth) next)

theorem erase_request_shape (A B C E : Type) [Fintype A] [Nonempty A]
    [Fintype B] [Nonempty B] [Fintype C] [Nonempty C] [Fintype E] [Nonempty E]
    {Result : Type} (reads : Nat)
    (prelude : A → B → NonleafProgram (OtherRawInput bound) Result)
    (counted : ∀ first second, NonleafProgram.readCount (prelude first second) ≤ reads)
    (key : Result → C → FullRawInput bound) (answer : E → DigestRegister)
    (stage : A → B → Result → C → E → V8Smz9HiddenLifetime.SourceByteStage bound)
    {queries requests : Nat}
    (next : ByteResult → V8Smz9HiddenLifetime.Lifetime bound Work queries requests) :
    V8Smz9HiddenPublicSimulator.erase
      (hiddenRequestShape A B C E reads prelude counted key answer stage next) =
    publicRequestShape A B C E reads prelude counted key answer
      (fun a b result c e => publicStage (stage a b result c e))
      (fun bytes => V8Smz9HiddenPublicSimulator.erase (next bytes)) := rfl

theorem erase_budget_transport {left right requests : Nat} (budget : left = right)
    (program : V8Smz9HiddenLifetime.Lifetime bound Work left requests) :
    V8Smz9HiddenPublicSimulator.erase (budget ▸ program) =
      budget ▸ V8Smz9HiddenPublicSimulator.erase program := by
  cases budget
  rfl

def publicHiddenRequest (largeEnough : 37434 ≤ bound)
    (request : PublicRequestData bound) {queries requests : Nat}
    (next : ByteResult → V8Smz9HiddenPublicSimulator.PublicLifetime bound Work queries requests) :
    V8Smz9HiddenPublicSimulator.PublicLifetime bound Work (16790291 + queries) (requests + 1) := by
  let built : V8Smz9HiddenPublicSimulator.PublicLifetime bound Work
      (8401585 + ((V8Smz9HiddenLifetime.byteCallCost + queries) + 1)) (requests + 1) :=
    publicRequestShape (LeafIndex → DigestRegister) (DecsFullCoefficients Goldilocks)
      (PiopCoefficients Goldilocks) DigestRegister 8401585
      (fun labels response => sourcePrefinal bound (by omega) request.statementBinding request.bindingFits
        request.salt labels response request.retainedRows request.rowBound)
      (fun labels response => source_fixed_prefinal_read_bound bound (by omega)
        request.statementBinding request.bindingFits request.salt labels response request.retainedRows request.rowBound)
      (fun stage transcript => sourceFinalKey bound (by omega) (sourceDigestPrefix stage.hashFpp) transcript)
      id (fun labels response stage => publicFinalByteStage largeEnough request labels stage response) next
  have budget : 8401585 + ((V8Smz9HiddenLifetime.byteCallCost + queries) + 1) =
      16790291 + queries := by
    unfold V8Smz9HiddenLifetime.byteCallCost
    omega
  exact budget ▸ built

theorem erase_hidden_request (largeEnough : 37434 ≤ bound)
    (request : V8Smz9SourceLifetime.SourceRequestData bound) {queries requests : Nat}
    (next : ByteResult → V8Smz9HiddenLifetime.Lifetime bound Work queries requests) :
    V8Smz9HiddenPublicSimulator.erase (hiddenRequest largeEnough request next) =
      publicHiddenRequest largeEnough (publicRequest request)
        (fun bytes => V8Smz9HiddenPublicSimulator.erase (next bytes)) := by
  unfold hiddenRequest publicHiddenRequest
  rw [erase_budget_transport, erase_request_shape]
  rfl

/-- Direct simulator compiler on the witness-free source syntax. -/
def compilePublicSource (largeEnough : 37434 ≤ bound) : {queries requests : Nat} →
    PublicLifetime bound Work queries requests →
      V8Smz9HiddenPublicSimulator.PublicLifetime bound Work queries requests
  | _, _, .finish event => .finish event
  | _, _, .gate operation next => .gate operation (compilePublicSource largeEnough next)
  | _, _, .quantumQuery next => .quantumQuery (compilePublicSource largeEnough next)
  | _, _, .honestRead input next => .honestRead input (fun answer => compilePublicSource largeEnough (next answer))
  | _, _, .instrument operation next => .instrument operation (fun outcome => compilePublicSource largeEnough (next outcome))
  | _, _, .random source next => .random source (fun coins => compilePublicSource largeEnough (next coins))
  | _, _, .sourceRequest request next =>
      publicHiddenRequest largeEnough request (fun bytes => compilePublicSource largeEnough (next bytes))

theorem erase_compiled_source (largeEnough : 37434 ≤ bound) {queries requests : Nat}
    (lifetime : V8Smz9SourceLifetime.Lifetime bound Work queries requests) :
    V8Smz9HiddenPublicSimulator.erase (compileHidden largeEnough lifetime) =
      compilePublicSource largeEnough (eraseSource lifetime) := by
  induction lifetime with
  | finish event => rfl
  | gate operation next ih => exact congrArg (V8Smz9HiddenPublicSimulator.PublicLifetime.gate operation) ih
  | quantumQuery next ih => exact congrArg V8Smz9HiddenPublicSimulator.PublicLifetime.quantumQuery ih
  | honestRead input next ih => exact congrArg (V8Smz9HiddenPublicSimulator.PublicLifetime.honestRead input) (funext ih)
  | instrument operation next ih => exact congrArg (V8Smz9HiddenPublicSimulator.PublicLifetime.instrument operation) (funext ih)
  | random source next ih => exact congrArg (V8Smz9HiddenPublicSimulator.PublicLifetime.random source) (funext ih)
  | sourceRequest request next ih =>
      simp only [compileHidden, eraseSource, compilePublicSource, erase_hidden_request]
      exact congrArg (publicHiddenRequest largeEnough (publicRequest request)) (funext ih)

def simulatorAcceptance (largeEnough : 37434 ≤ bound) {queries requests : Nat}
    (lifetime : PublicLifetime bound Work queries requests)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) : ℝ :=
  V8Smz9HiddenPublicSimulator.simulatorAcceptance (compilePublicSource largeEnough lifetime) initial

theorem source_simulator_is_public_world (largeEnough : 37434 ≤ bound) {queries requests : Nat}
    (lifetime : V8Smz9SourceLifetime.Lifetime bound Work queries requests)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) :
    simulatorAcceptance largeEnough (eraseSource lifetime) initial =
      V8Smz9HiddenLifetime.lifetimeAcceptance true (compileHidden largeEnough lifetime) initial := by
  unfold simulatorAcceptance
  rw [← erase_compiled_source, V8Smz9HiddenPublicSimulator.simulator_acceptance_is_public_world]

end
end HegemonCrypto.SmallWood.V8Smz9SourcePublicSimulator
