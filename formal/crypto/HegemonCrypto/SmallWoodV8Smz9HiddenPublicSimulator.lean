import HegemonCrypto.SmallWoodV8Smz9HiddenPublicErasure

/-! A directly compiled simulator whose input syntax contains no witness.

No private witness, validity proof, witness-selection function, or existence
oracle is an input to PublicLifetime, compilePublic, or simulatorAcceptance.
An explicit erasure theorem connects this independent public-only program
with the public world of an admitted source-stage lifetime. -/

namespace HegemonCrypto.SmallWood.V8Smz9HiddenPublicSimulator

open HegemonCrypto.CanonicalBytes
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9EagerOracleGame V8Smz9HonestWholeViewGames V8Smz9HonestFinalGame
open V8Smz9HonestRequestSchedule V8Smz9PostFinalProgram V8Smz9PostFinalPhysical
open V8Smz9BytePrefix V8Smz9PublicByteProgram V8Smz9PublicByteAccounting
open V8Smz9HiddenLifetime V8Smz9HiddenPublicErasure
open V8Smz9MeasuredSameOracleAdjacent
open V8Smz9MixedMaskCompiler (MixedProgram)
open scoped Classical

noncomputable section
set_option maxHeartbeats 500000
set_option maxRecDepth 10000
set_option Elab.async false

/-- The simulator's complete public input. Byte calls contain public stage
data only, and all adaptive branches remain part of the finite syntax. -/
inductive PublicLifetime (bound : Nat) (Work : Type) [Fintype Work] : Nat → Nat → Type 1 where
  | finish {queries requests : Nat}
      (event : Finset (QueryBasis (FullRawInput bound) DigestRegister Work)) :
      PublicLifetime bound Work queries requests
  | gate {queries requests : Nat}
      (operation : GameGate (Input := FullRawInput bound) (Work := Work))
      (next : PublicLifetime bound Work queries requests) : PublicLifetime bound Work queries requests
  | quantumQuery {queries requests : Nat}
      (next : PublicLifetime bound Work queries requests) : PublicLifetime bound Work (queries + 1) requests
  | honestRead {queries requests : Nat} (input : FullRawInput bound)
      (next : DigestRegister → PublicLifetime bound Work queries requests) :
      PublicLifetime bound Work (queries + 1) requests
  | instrument {queries requests count : Nat}
      (operation : Instrument (FullRawInput bound) Work count)
      (next : Fin count → PublicLifetime bound Work queries requests) :
      PublicLifetime bound Work queries requests
  | random {queries requests : Nat} (source : RandomSource)
      (next : source.Coins → PublicLifetime bound Work queries requests) :
      PublicLifetime bound Work queries requests
  | write {queries requests : Nat} (input : FullRawInput bound) (answer : DigestRegister)
      (next : PublicLifetime bound Work queries requests) : PublicLifetime bound Work (queries + 1) requests
  | nonleaf {queries requests : Nat} {Result : Type} (reads : Nat)
      (program : NonleafProgram (OtherRawInput bound) Result)
      (counted : NonleafProgram.readCount program ≤ reads)
      (next : Result → PublicLifetime bound Work queries requests) :
      PublicLifetime bound Work (reads + queries) requests
  | byteCall {queries requests : Nat} (stage : PublicByteStage bound)
      (next : ByteResult → PublicLifetime bound Work queries requests) :
      PublicLifetime bound Work (byteCallCost + queries) (requests + 1)

variable {bound : Nat} {Work : Type} [Fintype Work]

/-- The public byte compiler is used directly, without constructing an
admitted source byte job or supplying a witness. -/
def buildPublicByteCall {queries : Nat} (stage : PublicByteStage bound)
    (next : ByteResult → BoundedMixed bound Work queries) :
    BoundedMixed bound Work (byteCallCost + queries) :=
  ⟨publicByteProgram false bound (stage.withNext (futureGames next)),
    (public_byte_program_query_bound false bound (stage.withNext (futureGames next)) queries
      (future_games_query_bound next)).trans
        (Nat.add_le_add_right public_cost_le_byte_call_cost queries)⟩

def compilePublic : {queries requests : Nat} →
    PublicLifetime bound Work queries requests → BoundedMixed bound Work queries
  | _, _, .finish event => ⟨.finish event, Nat.zero_le _⟩
  | _, _, .gate operation next =>
      ⟨.gate operation (compilePublic next).1, (compilePublic next).2⟩
  | _, _, .quantumQuery next =>
      ⟨.quantumQuery (compilePublic next).1, Nat.add_le_add_right (compilePublic next).2 1⟩
  | _, _, .honestRead input next =>
      ⟨.honestRead input (fun answer => (compilePublic (next answer)).1),
        Nat.add_le_add_right (Finset.sup_le fun answer _ => (compilePublic (next answer)).2) 1⟩
  | _, _, .instrument operation next =>
      ⟨.instrument operation (fun outcome => (compilePublic (next outcome)).1),
        Finset.sup_le fun outcome _ => (compilePublic (next outcome)).2⟩
  | _, _, .random source next =>
      ⟨.random source (fun coins => (compilePublic (next coins)).1),
        Finset.sup_le fun coins _ => (compilePublic (next coins)).2⟩
  | _, _, .write input answer next =>
      ⟨.write input answer (compilePublic next).1, Nat.add_le_add_right (compilePublic next).2 1⟩
  | _, _, .nonleaf reads program counted next =>
      ⟨compileNonleaf program (fun result => (compilePublic (next result)).1),
        (mixed_nonleaf_query_bound program _ _ (fun result => (compilePublic (next result)).2)).trans
          (Nat.add_le_add_right counted _)⟩
  | _, _, .byteCall stage next =>
      buildPublicByteCall stage (fun bytes => compilePublic (next bytes))

theorem public_compiler_query_bound {queries requests : Nat}
    (lifetime : PublicLifetime bound Work queries requests) :
    V8Smz9MixedMaskCompiler.queryCount (compilePublic lifetime).1 ≤ queries :=
  (compilePublic lifetime).2

/-- Erasure forgets witness and validity-proof fields and retains every
public action and continuation. It performs no witness search or sampling. -/
def erase : {queries requests : Nat} → Lifetime bound Work queries requests →
    PublicLifetime bound Work queries requests
  | _, _, .finish event => .finish event
  | _, _, .gate operation next => .gate operation (erase next)
  | _, _, .quantumQuery next => .quantumQuery (erase next)
  | _, _, .honestRead input next => .honestRead input (fun answer => erase (next answer))
  | _, _, .instrument operation next => .instrument operation (fun outcome => erase (next outcome))
  | _, _, .random source next => .random source (fun coins => erase (next coins))
  | _, _, .write input answer next => .write input answer (erase next)
  | _, _, .nonleaf reads program counted next => .nonleaf reads program counted (fun result => erase (next result))
  | _, _, .byteCall stage next => .byteCall (publicStage stage) (fun bytes => erase (next bytes))

theorem build_public_byte_erasure {queries : Nat} (stage : SourceByteStage bound)
    (left right : ByteResult → BoundedMixed bound Work queries)
    (remaining : ∀ bytes, (left bytes).1 = (right bytes).1) :
    (buildPublicByteCall (publicStage stage) left).1 = (buildByteCall true stage right).1 := by
  have futureEqual : futureGames left = futureGames right := by
    funext bytes
    exact congrArg (fun program => V8Smz9MixedMaskCompiler.compile program []) (remaining bytes)
  change publicByteProgram false bound ((publicStage stage).withNext (futureGames left)) =
    publicByteProgram false bound (stage.toJob right).toPublicBytePivot
  rw [source_job_public_projection, futureEqual]

/-- Exact compiled equality with the public-only simulator. The right side
is not used as the simulator definition and no witness is recovered on the left. -/
theorem compile_public_erasure {queries requests : Nat}
    (lifetime : Lifetime bound Work queries requests) :
    (compilePublic (erase lifetime)).1 = (compileWorld true lifetime).1 := by
  induction lifetime with
  | finish event => rfl
  | gate operation next ih => exact congrArg (MixedProgram.gate operation) ih
  | quantumQuery next ih => exact congrArg MixedProgram.quantumQuery ih
  | honestRead input next ih => exact congrArg (MixedProgram.honestRead input) (funext ih)
  | instrument operation next ih => exact congrArg (MixedProgram.instrument operation) (funext ih)
  | random source next ih => exact congrArg (MixedProgram.random source) (funext ih)
  | write input answer next ih => exact congrArg (MixedProgram.write input answer) ih
  | nonleaf reads program counted next ih => exact congrArg (compileNonleaf program) (funext ih)
  | byteCall stage next ih => exact build_public_byte_erasure stage _ _ ih

theorem erase_eq_of_publicly_equivalent {queries requests : Nat}
    {left right : Lifetime bound Work queries requests} (related : PubliclyEquivalent left right) :
    erase left = erase right := by
  induction related with
  | finish event => rfl
  | gate operation next ih => exact congrArg (PublicLifetime.gate operation) ih
  | quantumQuery next ih => exact congrArg PublicLifetime.quantumQuery ih
  | honestRead input next ih => exact congrArg (PublicLifetime.honestRead input) (funext ih)
  | instrument operation next ih => exact congrArg (PublicLifetime.instrument operation) (funext ih)
  | random source next ih => exact congrArg (PublicLifetime.random source) (funext ih)
  | write input answer next ih => exact congrArg (PublicLifetime.write input answer) ih
  | nonleaf reads program counted next ih => exact congrArg (PublicLifetime.nonleaf reads program counted) (funext ih)
  | byteCall leftStage rightStage same next ih =>
      change PublicLifetime.byteCall (publicStage leftStage) _ = PublicLifetime.byteCall (publicStage rightStage) _
      rw [same]
      exact congrArg (PublicLifetime.byteCall (publicStage rightStage)) (funext ih)

/-- A simulator experiment with a public-only input and one initial oracle
draw. The initial state is an explicit common environment state, not a witness. -/
def simulatorAcceptance {queries requests : Nat}
    (lifetime : PublicLifetime bound Work queries requests)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) : ℝ :=
  V8Smz9MixedMaskCompiler.acceptance false (compilePublic lifetime).1 initial

theorem simulator_acceptance_is_public_world {queries requests : Nat}
    (lifetime : Lifetime bound Work queries requests)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) :
    simulatorAcceptance (erase lifetime) initial = lifetimeAcceptance true lifetime initial := by
  unfold simulatorAcceptance lifetimeAcceptance
  rw [compile_public_erasure]

end
end HegemonCrypto.SmallWood.V8Smz9HiddenPublicSimulator
