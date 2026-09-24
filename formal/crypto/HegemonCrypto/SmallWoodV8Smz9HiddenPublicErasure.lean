import HegemonCrypto.SmallWoodV8Smz9HiddenLifetime

/-! Explicit public-data noninterference for the hidden-byte lifetime.

The relation below requires the same public stage fields, native action
data, and every recursively selected byte/measurement/random branch. Private
witnesses and packed-domain proofs may differ. This is an explicit premise
to be established by an eventual source transport; it is not inferred merely
because a compiler world has been named public. -/

namespace HegemonCrypto.SmallWood.V8Smz9HiddenPublicErasure

open HegemonCrypto.CanonicalBytes
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9ZeroKnowledge V8Smz9MeasuredSameOracleAdjacent
open V8Smz9HonestHybrid (DecsGamma DecsFullCoefficients)
open V8Smz9EagerPrivacy V8Smz9EagerOracleGame V8Smz9RuntimeRandomness
open V8Smz9HonestWholeViewGames V8Smz9HonestFinalGame V8Smz9HonestRequestSchedule
open V8Smz9PostFinalProgram V8Smz9PostFinalPhysical V8Smz9BytePrefix
open V8Smz9PublicByteProgram V8Smz9HiddenLifetime
open V8Smz9MixedMaskCompiler (MixedProgram)
open scoped Classical

noncomputable section
set_option maxHeartbeats 500000
set_option maxRecDepth 10000
set_option Elab.async false

/-- Every field retained by the public byte implementation. There is no
private witness, packed-domain proof, future closure, oracle or state. -/
structure PublicByteStage (bound : Nat) where
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

variable {bound : Nat} {Work : Type} [Fintype Work]

def publicStage (stage : SourceByteStage bound) : PublicByteStage bound where
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

def PublicByteStage.withNext (stage : PublicByteStage bound) (next : ByteFuture (Work := Work) bound) :
    PublicBytePivot (Work := Work) bound where
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
  next := next

/-- Public byte jobs factor through an actual witness-erasing projection. -/
theorem source_job_public_projection {queries : Nat} (stage : SourceByteStage bound)
    (next : ByteResult → BoundedMixed bound Work queries) :
    (stage.toJob next).toPublicBytePivot = (publicStage stage).withNext (futureGames next) := rfl

theorem public_jobs_equal {queries : Nat} (left right : SourceByteStage bound)
    (same : publicStage left = publicStage right)
    (leftNext rightNext : ByteResult → BoundedMixed bound Work queries)
    (remaining : ∀ bytes, (leftNext bytes).1 = (rightNext bytes).1) :
    (left.toJob leftNext).toPublicBytePivot = (right.toJob rightNext).toPublicBytePivot := by
  have futureEqual : futureGames leftNext = futureGames rightNext := by
    funext bytes
    exact congrArg (fun program => V8Smz9MixedMaskCompiler.compile program []) (remaining bytes)
  rw [source_job_public_projection, source_job_public_projection, same, futureEqual]

theorem build_byte_public_congr {queries : Nat} (left right : SourceByteStage bound)
    (same : publicStage left = publicStage right)
    (leftNext rightNext : ByteResult → BoundedMixed bound Work queries)
    (remaining : ∀ bytes, (leftNext bytes).1 = (rightNext bytes).1) :
    (buildByteCall true left leftNext).1 = (buildByteCall true right rightNext).1 := by
  change publicByteProgram false bound (left.toJob leftNext).toPublicBytePivot =
    publicByteProgram false bound (right.toJob rightNext).toPublicBytePivot
  exact congrArg (publicByteProgram false bound) (public_jobs_equal left right same leftNext rightNext remaining)

/-- A public-control-flow relation. All public choices and every possible
continuation must match; only the byte stage's private witness/proof are
erased. Thus witness-dependent public choices cannot satisfy it silently. -/
inductive PubliclyEquivalent : {queries requests : Nat} →
    Lifetime bound Work queries requests → Lifetime bound Work queries requests → Prop where
  | finish {queries requests : Nat}
      (event : Finset (QueryBasis (FullRawInput bound) DigestRegister Work)) :
      PubliclyEquivalent (.finish (queries := queries) (requests := requests) event) (.finish event)
  | gate {queries requests : Nat} {left right : Lifetime bound Work queries requests}
      (operation : GameGate (Input := FullRawInput bound) (Work := Work))
      (next : PubliclyEquivalent left right) : PubliclyEquivalent (.gate operation left) (.gate operation right)
  | quantumQuery {queries requests : Nat} {left right : Lifetime bound Work queries requests}
      (next : PubliclyEquivalent left right) : PubliclyEquivalent (.quantumQuery left) (.quantumQuery right)
  | honestRead {queries requests : Nat}
      {left right : DigestRegister → Lifetime bound Work queries requests}
      (input : FullRawInput bound) (next : ∀ answer, PubliclyEquivalent (left answer) (right answer)) :
      PubliclyEquivalent (.honestRead input left) (.honestRead input right)
  | instrument {queries requests count : Nat}
      {left right : Fin count → Lifetime bound Work queries requests}
      (operation : Instrument (FullRawInput bound) Work count)
      (next : ∀ outcome, PubliclyEquivalent (left outcome) (right outcome)) :
      PubliclyEquivalent (.instrument operation left) (.instrument operation right)
  | random {queries requests : Nat} (source : RandomSource)
      {left right : source.Coins → Lifetime bound Work queries requests}
      (next : ∀ coins, PubliclyEquivalent (left coins) (right coins)) :
      PubliclyEquivalent (.random source left) (.random source right)
  | write {queries requests : Nat} {left right : Lifetime bound Work queries requests}
      (input : FullRawInput bound) (answer : DigestRegister) (next : PubliclyEquivalent left right) :
      PubliclyEquivalent (.write input answer left) (.write input answer right)
  | nonleaf {queries requests : Nat} {Result : Type}
      {left right : Result → Lifetime bound Work queries requests} (reads : Nat)
      (program : NonleafProgram (OtherRawInput bound) Result)
      (counted : NonleafProgram.readCount program ≤ reads)
      (next : ∀ result, PubliclyEquivalent (left result) (right result)) :
      PubliclyEquivalent (.nonleaf reads program counted left) (.nonleaf reads program counted right)
  | byteCall {queries requests : Nat}
      {left right : ByteResult → Lifetime bound Work queries requests}
      (leftStage rightStage : SourceByteStage bound) (same : publicStage leftStage = publicStage rightStage)
      (next : ∀ bytes, PubliclyEquivalent (left bytes) (right bytes)) :
      PubliclyEquivalent (.byteCall leftStage left) (.byteCall rightStage right)

/-- The compiled public program depends only on the explicit public
control-flow relation, not on either stage's private witness or its proof. -/
theorem compiled_public_eq_of_publicly_equivalent {queries requests : Nat}
    {left right : Lifetime bound Work queries requests} (related : PubliclyEquivalent left right) :
    (compileWorld true left).1 = (compileWorld true right).1 := by
  induction related with
  | finish event => rfl
  | gate operation next ih => exact congrArg (MixedProgram.gate operation) ih
  | quantumQuery next ih => exact congrArg MixedProgram.quantumQuery ih
  | honestRead input next ih =>
      exact congrArg (MixedProgram.honestRead input) (funext ih)
  | instrument operation next ih =>
      exact congrArg (MixedProgram.instrument operation) (funext ih)
  | random source next ih => exact congrArg (MixedProgram.random source) (funext ih)
  | write input answer next ih => exact congrArg (MixedProgram.write input answer) ih
  | nonleaf reads program counted next ih => exact congrArg (compileNonleaf program) (funext ih)
  | byteCall leftStage rightStage same next ih =>
      exact build_byte_public_congr leftStage rightStage same _ _ ih

theorem public_run_eq_of_publicly_equivalent {queries requests : Nat}
    {left right : Lifetime bound Work queries requests} (related : PubliclyEquivalent left right)
    (oracle : FullOracle bound) (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    runLifetime true left oracle state = runLifetime true right oracle state := by
  unfold runLifetime
  rw [compiled_public_eq_of_publicly_equivalent related]

theorem public_acceptance_eq_of_publicly_equivalent {queries requests : Nat}
    {left right : Lifetime bound Work queries requests} (related : PubliclyEquivalent left right)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) :
    lifetimeAcceptance true left initial = lifetimeAcceptance true right initial := by
  unfold lifetimeAcceptance
  rw [compiled_public_eq_of_publicly_equivalent related]

end
end HegemonCrypto.SmallWood.V8Smz9HiddenPublicErasure
