import Q38Rp05CurrentPrefinal
import Q38Rp05CurrentPostfinal
/-!
# Current SMZA physical-request component

This source module contains one declaration layer of the complete RP05
request. Definitions and proof statements are preserved unchanged.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch (LeafIndex)
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame (SaltBytes)
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9HonestOpeningSchedule
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewFinalInput
open HegemonCrypto.SmallWood.V8Smz9RawCounterCompiler
open HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05RequestCompiler
open HegemonCrypto.SmallWood.Q38Rp05CurrentPrefinal
open HegemonCrypto.SmallWood.Q38Rp05CurrentPostfinal
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open Hegemon.Transaction.Poseidon2V8RelationProgram
open scoped Classical
local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

/-- The same structural compiler as the historical one, but with the
corrected input partition throughout the continuation. -/
def compileCurrentNonleaf {bound : Nat} {Result Work : Type} [Fintype Work] :
    NonleafProgram (Rp05OtherRawInput bound) Result →
      (Result → Program (Rp05FullRawInput bound) Work) →
        Program (Rp05FullRawInput bound) Work
  | .done result, next => next result
  | .read input rest, next =>
      .honestRead (Sum.inr input)
        (fun output => compileCurrentNonleaf (rest output) next)

theorem compile_current_nonleaf_execution
    {bound : Nat} {Result Work : Type} [Fintype Work]
    (randomized : Bool)
    (program : NonleafProgram (Rp05OtherRawInput bound) Result)
    (next : Result → Program (Rp05FullRawInput bound) Work)
    (oracle : Rp05FullRawInput bound → DigestRegister)
    (state : GameState
      (Input := Rp05FullRawInput bound) (Work := Work)) :
    run randomized (compileCurrentNonleaf program next) oracle state =
      run randomized
        (next (NonleafProgram.interpret
          (fun input => oracle (Sum.inr input)) program)) oracle state := by
  induction program with
  | done result => rfl
  | read input rest ih => exact ih _

end
end HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest

