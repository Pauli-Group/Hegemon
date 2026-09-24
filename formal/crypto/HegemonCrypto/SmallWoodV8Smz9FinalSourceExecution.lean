import HegemonCrypto.SmallWoodV8Smz9FinalSourceRequestBridge

namespace HegemonCrypto.SmallWood.V8Smz9FinalLifetime

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9CurrentPrivacyComposition V8Smz9EagerPrivacy V8Smz9EagerOracleGame
open V8Smz9CurrentPublicContext
open V8Smz9HonestWholeViewGames (GameState Program RandomSource)
open V8Smz9HonestFinalGame V8Smz9SourceLifetime V8Smz9PostFinalQueryBudget
open scoped Classical

noncomputable section
set_option maxHeartbeats 500000
set_option maxRecDepth 10000
set_option Elab.async false

variable {bound : Nat} {Work : Type} [Fintype Work]

def ordinaryRandomPair (A B : Type) [Fintype A] [Nonempty A] [Fintype B] [Nonempty B]
    (next : A → B → Program (FullRawInput bound) Work) : Program (FullRawInput bound) Work :=
  .random ⟨A, inferInstance, inferInstance⟩ fun first =>
    .random ⟨B, inferInstance, inferInstance⟩ (next first)

theorem ordinary_random_pair_execution (A B : Type) [Fintype A] [Nonempty A] [Fintype B] [Nonempty B]
    (mode : Bool) (next : A → B → Program (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9HonestWholeViewGames.run mode (ordinaryRandomPair A B next) oracle state =
      uniformAverage (fun first : A => uniformAverage (fun second : B =>
        V8Smz9HonestWholeViewGames.run mode (next first second) oracle state)) := rfl

attribute [local irreducible] V8Smz9HonestWholeViewGames.run sourceCompleteByteRequest
  actualRequestCompiler compileSource

/-- Expose only the two local random instructions of the actual request
compiler. The concrete complete-byte program is not unfolded below them. -/
theorem actual_request_program_is_random_pair (largeEnough : 37434 ≤ bound)
    (request : SourceRequestData bound)
    (next : V8Smz9SourceLifetime.ByteResult → Program (FullRawInput bound) Work) :
    actualRequestCompiler largeEnough request next =
      ordinaryRandomPair (SourceRemainingCoins Goldilocks) (JointMaskCoins Goldilocks)
        (fun coins masks => sourceCompleteByteRequest bound largeEnough request.statementBinding request.bindingFits
          request.statement (packingValues request.witness) coins masks request.salt request.retainedRows request.rowBound
          next) := by
  simp only [actualRequestCompiler, ordinaryRandomPair, remainingCoinsSource, jointMasksSource]

/-- Generic request execution for an arbitrary ordinary-program future.
This uses the symbolic random-pair execution law, without reducing the
physical interpreter on the concrete leaf/source request. -/
theorem actual_request_execution_explicit (largeEnough : 37434 ≤ bound)
    (request : SourceRequestData bound)
    (next : V8Smz9SourceLifetime.ByteResult → Program (FullRawInput bound) Work) (mode : Bool)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9HonestWholeViewGames.run mode (actualRequestCompiler largeEnough request next) oracle state =
      uniformAverage (fun coins : SourceRemainingCoins Goldilocks =>
        uniformAverage (fun masks : JointMaskCoins Goldilocks =>
          V8Smz9HonestWholeViewGames.run mode
            (sourceCompleteByteRequest bound largeEnough request.statementBinding request.bindingFits
              request.statement (packingValues request.witness) coins masks request.salt request.retainedRows request.rowBound
              next) oracle state)) := by
  rw [actual_request_program_is_random_pair, ordinary_random_pair_execution]

theorem source_request_program_is_random_pair (largeEnough : 37434 ≤ bound)
    {queries requests : Nat} (request : SourceRequestData bound)
    (next : V8Smz9SourceLifetime.ByteResult → Lifetime bound Work queries requests) :
    compileSource largeEnough (.sourceRequest request next) =
      ordinaryRandomPair (SourceRemainingCoins Goldilocks) (JointMaskCoins Goldilocks)
        (fun coins masks => sourceCompleteByteRequest bound largeEnough request.statementBinding request.bindingFits
          request.statement (packingValues request.witness) coins masks request.salt request.retainedRows request.rowBound
          (fun bytes => compileSource largeEnough (next bytes))) := by
  simp only [compileSource, compileWith, actualRequestCompiler, ordinaryRandomPair, remainingCoinsSource, jointMasksSource]

theorem source_request_execution_explicit (largeEnough : 37434 ≤ bound)
    {queries requests : Nat} (request : SourceRequestData bound)
    (next : V8Smz9SourceLifetime.ByteResult → Lifetime bound Work queries requests) (mode : Bool)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9HonestWholeViewGames.run mode (compileSource largeEnough (.sourceRequest request next)) oracle state =
      uniformAverage (fun coins : SourceRemainingCoins Goldilocks =>
        uniformAverage (fun masks : JointMaskCoins Goldilocks =>
          V8Smz9HonestWholeViewGames.run mode
            (sourceCompleteByteRequest bound largeEnough request.statementBinding request.bindingFits
              request.statement (packingValues request.witness) coins masks request.salt request.retainedRows request.rowBound
              (fun bytes => compileSource largeEnough (next bytes))) oracle state)) := by
  rw [source_request_program_is_random_pair, ordinary_random_pair_execution]


end
end HegemonCrypto.SmallWood.V8Smz9FinalLifetime
