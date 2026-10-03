import Q38Rp05CurrentTailDefinition
/-!
# Current SMZA post-final request layer

This module is one declaration layer of the current request program. The
moved declaration and any proof statement are preserved unchanged.
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

/-- Fixed-oracle output of the complete post-leaf request. It reads the
SMZA prefinal and final keys, then the current nonce and index schedules. -/
def currentRequestResult
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (tapes : LeafIndex → LeafTape)
    (labels : LeafIndex → DigestRegister)
    (oracle : Rp05FullRawInput bound → DigestRegister) :
    Except String (List Byte) :=
  currentTwoReadResult
    (rp05CurrentPrefinal bound largeEnough dsl statement salt labels
      values base masks widthBound)
    (fun computed =>
      let coefficients := Q38Rp05RequestCompiler.transcript dsl statement
        values base masks computed.1.piopGamma
      currentFinalKey bound (by omega) computed.1.hashFpp coefficients)
    (fun computed digest =>
      let coefficients := Q38Rp05RequestCompiler.transcript dsl statement
        values base masks computed.1.piopGamma
      let parameters := decodedParameters dsl statement computed.1.piopGamma
      let gamma := decodedQ38DecsGamma computed.1.decsGamma
      let pending := sourcePendingFailure
        (sourcePendingFailure false computed.1.decsGamma)
        computed.1.piopGamma
      currentHonestPostFinalProgram bound largeEnough dsl statement parameters
        values base masks.1 gamma computed.2 coefficients digest pending salt
        computed.1.tree tapes)
    oracle


end
end HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
