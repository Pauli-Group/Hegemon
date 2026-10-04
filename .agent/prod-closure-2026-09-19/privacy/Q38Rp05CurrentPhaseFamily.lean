import Q38Rp05CurrentCompleteProgram
import Q38ConcreteAdaptivePrivacy
import Q38Rp05ExecutionBridge

/-!
# current_complete_request_phase_run_family

This theorem is isolated from the request compiler to bound per-module Lean
elaboration memory. Its statement and proof are moved unchanged.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9HonestOpeningSchedule
open HegemonCrypto.SmallWood.V8Smz9RawCounterCompiler
open HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy
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

/-- The entire corrected current request, not only its nonleaf suffix, runs
on each fiber of the same reached total-oracle family. This includes sampled
q38 coins, the persistent 2511-byte leaf batch, DECS/PIOP/final reads and
both post-final abort branches; no fresh physical oracle is introduced. -/
theorem current_complete_request_phase_run_family
    {bound : Nat} {Work : Type} [Fintype Work] [DecidableEq Work]
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (next : Except String (List Byte) →
      Program (Rp05FullRawInput bound) Work)
    (family : OracleRegisterFamily
      (Input := Rp05FullRawInput bound) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work)) :
    phaseRun true
        (currentCompleteHonestRequest largeEnough dsl statement values salt
          widthBound next)
        (phaseEncode (totalOracleFamilyState family)) =
      uniformAverage (fun oracle : Rp05FullRawInput bound → DigestRegister =>
        V8Smz9HonestWholeViewGames.run true
          (currentCompleteHonestRequest largeEnough dsl statement values salt
            widthBound next)
          oracle (familyGameState family oracle)) := by
  rw [phase_run_eq_database_run, phase_decode_encode,
    databaseRun_totalOracleFamilyState]
  apply congrArg uniformAverage
  funext oracle
  rw [databaseRun_oracleState]


end
end HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
