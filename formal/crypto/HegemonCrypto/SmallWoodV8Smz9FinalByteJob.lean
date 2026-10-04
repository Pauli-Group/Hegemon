import HegemonCrypto.SmallWoodV8Smz9FinalContinuation
import HegemonCrypto.SmallWoodV8Smz9FinalSourceRequestBridge
import HegemonCrypto.SmallWoodV8Smz9SourceByteProgram

/-! The actual selected-final stage supplies the hidden-byte pivot's job.
Every stage field is retained from execution. The admitted request supplies
the same witness/public relation, and the whole mixed future is compiled into
the ordinary observer with a derived raw-query bound. -/

namespace HegemonCrypto.SmallWood.V8Smz9FinalLifetime

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9CurrentPrivacyComposition V8Smz9EagerPrivacy V8Smz9EagerOracleGame
open V8Smz9HonestRequestSchedule V8Smz9HonestFinalGame V8Smz9HonestHybrid
open V8Smz9HonestOpeningSchedule V8Smz9CurrentPublicContext V8Smz9PostFinalProgram
open V8Smz9DynamicPhysicalTransport V8Smz9MixedFinalOperational V8Smz9SourceLifetime
open V8Smz9DynamicRequest
open V8Smz9BytePrefix V8Smz9SourceByteProgram V8Smz9PublicByteProgram
open V8Smz9HonestWholeViewGames (GameState)
open V8Smz9MixedMaskCompiler (MixedProgram)
open scoped Classical

noncomputable section
set_option maxHeartbeats 600000
set_option maxRecDepth 10000
set_option Elab.async false

variable {bound : Nat} {Work : Type} [Fintype Work]

/-- No oracle or branch state is a field. The input stage, D and full T are
the exact values supplied by the pre-final program and selected final event. -/
def finalByteJob (largeEnough : 37434 ≤ bound) (request : SourceRequestData bound)
    (labels : LeafIndex → DigestRegister) (stage : PrefinalResult)
    (response : DecsFullCoefficients Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (digest : DigestRegister) (queries : Nat)
    (next : V8Smz9MixedFinalOperational.ByteResult → MixedProgram (FullRawInput bound) Work)
    (remaining : ∀ bytes, V8Smz9MixedMaskCompiler.queryCount (next bytes) ≤ queries) :
    BytePivotJob (Work := Work) bound queries where
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
  next := fun bytes => V8Smz9MixedMaskCompiler.compile (next bytes) []
  witness := request.witness
  domain := request.domain
  bounded := fun bytes => (V8Smz9MixedMaskCompiler.compiled_query_count_le (next bytes) []).trans (remaining bytes)

attribute [local irreducible] V8Smz9MixedMaskCompiler.run V8Smz9HonestWholeViewGames.run
  V8Smz9MixedMaskCompiler.actualLeafWrites nonleafCompile sourcePostFinalBytesProgram
  NonleafProgram.compile actualLeafOverlay

/-- A syntactic bridge: the job's all-current-leaf source byte program is
the same after-final source program with its complete mixed future held true. -/
theorem fixed_compiled_after_final_is_source_byte_program
    (largeEnough : 37434 ≤ bound) (request : SourceRequestData bound)
    (labels : LeafIndex → DigestRegister) (stage : PrefinalResult)
    (response : DecsFullCoefficients Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (digest : DigestRegister) (queries : Nat)
    (next : V8Smz9MixedFinalOperational.ByteResult → MixedProgram (FullRawInput bound) Work)
    (remaining : ∀ bytes, V8Smz9MixedMaskCompiler.queryCount (next bytes) ≤ queries) :
    afterFinal (requestContext largeEnough request) labels stage response transcript digest
      (fun bytes => V8Smz9MixedMaskCompiler.fixedProgram true (V8Smz9MixedMaskCompiler.compile (next bytes) [])) =
    sourceByteProgram true bound queries
      (finalByteJob largeEnough request labels stage response transcript digest queries next remaining) := by
  simp only [afterFinal, randomPair, uniformCoins, sourceByteProgram, finiteCoins, finalByteJob,
    requestContext, nonleaf_compile_fixed_program, postFinalBytes, sourcePostFinalProgram,
    recoveredMasks, byteRecoveredMasks]

/-- The actual after-final execution equals the concrete source side of the
byte pivot for every logical oracle and every subnormalized branch state.
The ordinary observer starts at that SAME logical table; this mathematical
observer adapter does not reset the log of the actual whole-lifetime program. -/
theorem after_final_is_source_byte_job (outerMode : Bool)
    (largeEnough : 37434 ≤ bound) (request : SourceRequestData bound)
    (labels : LeafIndex → DigestRegister) (stage : PrefinalResult)
    (response : DecsFullCoefficients Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (digest : DigestRegister) (queries : Nat)
    (next : V8Smz9MixedFinalOperational.ByteResult → MixedProgram (FullRawInput bound) Work)
    (remaining : ∀ bytes, V8Smz9MixedMaskCompiler.queryCount (next bytes) ≤ queries)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run true
      (afterFinal (requestContext largeEnough request) labels stage response transcript digest next) oracle state =
    V8Smz9MixedMaskCompiler.run outerMode
      (sourceByteProgram true bound queries
        (finalByteJob largeEnough request labels stage response transcript digest queries next remaining)) oracle state := by
  calc
    _ = V8Smz9MixedMaskCompiler.run true
        (afterFinal (requestContext largeEnough request) labels stage response transcript digest
          (fun bytes => V8Smz9MixedMaskCompiler.fixedProgram true (V8Smz9MixedMaskCompiler.compile (next bytes) [])))
        oracle state := by
      apply after_final_continuation_congr
      intro bytes current currentState
      rw [V8Smz9MixedMaskCompiler.fixed_program_execution,
        V8Smz9MixedMaskCompiler.compile_executes, V8Smz9MixedMaskCompiler.effective_empty]
    _ = _ := by
      rw [fixed_compiled_after_final_is_source_byte_program largeEnough request labels stage response transcript digest
        queries next remaining]
      rw [source_byte_program_executes_raw_kernel, source_byte_program_executes_raw_kernel]


end
end HegemonCrypto.SmallWood.V8Smz9FinalLifetime
