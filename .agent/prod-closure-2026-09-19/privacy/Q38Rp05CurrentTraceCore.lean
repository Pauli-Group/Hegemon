import Q38Rp05CurrentPrefinal
import Q38Rp05FinalPrivacyInstrument
import Q38Rp05MeasuredInstrument

/-! A compact, shared core for the current trace path. These two lemmas are
the only CurrentTrace declarations needed by prefix instrumentation and the
initialized DECS/PIOP composition; the larger trace-analysis module stays
out of their import chain. -/
namespace HegemonCrypto.SmallWood.Q38Rp05CurrentTrace

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch (LeafIndex)
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame (SaltBytes)
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9RawCounterCompiler
open HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.V8SmzaOpenedRows
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05RequestCompiler
open HegemonCrypto.SmallWood.Q38Rp05CurrentPrefinal
open HegemonCrypto.SmallWood.Q38Rp05FinalPrivacyInstrument
open HegemonCrypto.SmallWood.Q38Rp05MeasuredInstrument
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open scoped BigOperators Classical

local notation "Statement" =>
  HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

/-- The actual current prefinal program is DECS prefix, the public D reply,
then the D-indexed PIOP suffix on the same corrected oracle carrier. -/
theorem current_prefinal_is_staged
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (salt : SaltBytes)
    (labels : LeafIndex → DigestRegister)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (widthBound : 5 * dsl.width statement ≤ 2 ^ 24) :
    rp05CurrentPrefinal bound largeEnough dsl statement salt labels values
        base masks widthBound =
      let shape := rp05CurrentPrefinalShape bound largeEnough dsl statement
        salt labels widthBound
      NonleafProgram.bind (decsPrefix shape) fun stage =>
        NonleafProgram.bind
          (piopSuffix shape stage
            (decsReply values base masks stage.decsGamma)) fun result =>
            .done (result, decsReply values base masks stage.decsGamma) := by
  unfold rp05CurrentPrefinal
  exact dynamic_eq_decs_then_piop _ _

/-- The DECS trace restriction and the subsequent response-indexed PIOP
measurement act on one family in source order. This equality retains the
entire residual state and the stage chosen from the DECS trace. -/
theorem current_decs_then_piop_branch_family
    {bound : Nat} {Work : Type} [Fintype Work] [DecidableEq Work]
    (shape : Q38PrefinalShape (Rp05OtherRawInput bound))
    (decsFuel piopFuel : Nat)
    (decsTrace : PublicTrace DigestRegister decsFuel)
    (stageOf : PublicTrace DigestRegister decsFuel → DecsStage)
    (enough : ∀ reply : D,
      NonleafProgram.readCount
        (piopSuffix shape (stageOf decsTrace) reply) ≤ piopFuel)
    (family : OracleRegisterFamily
      (Input := Rp05FullRawInput bound) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := D × Work))
    (reply : D) (piopTrace : PublicTrace DigestRegister piopFuel) :
    let decsFamily :=
      traceFamily Sum.inr decsFuel (decsPrefix shape) decsTrace family
    (rp05PiopMeasuredInstrument piopFuel shape (stageOf decsTrace) enough).branch
      (reply, piopTrace)
        (HegemonCrypto.SmallWood.Q38Rp05FinalPrivacyInstrument.phaseTraceState
          Sum.inr decsFuel (decsPrefix shape) decsTrace
          (phaseEncode (totalOracleFamilyState family))) =
      phaseEncode (totalOracleFamilyState
        (measuredBranchFamily (Input := Rp05FullRawInput bound)
          (Public := D) (BaseWork := Work) Sum.inr piopFuel
          (fun response => piopSuffix shape (stageOf decsTrace) response)
          (reply, piopTrace) decsFamily)) := by
  let decsFamily :=
    traceFamily Sum.inr decsFuel (decsPrefix shape) decsTrace family
  dsimp only
  simp only [HegemonCrypto.SmallWood.Q38Rp05FinalPrivacyInstrument.phaseTraceState,
    HegemonCrypto.SmallWood.Q38Rp05FinalPrivacyInstrument.traceFamily]
  erw [HegemonCrypto.SmallWood.Q38Rp05MeasuredInstrument.phase_trace_total_oracle_family
    (Input := Rp05FullRawInput bound) (BaseWork := D × Work)
    Sum.inr decsFuel (decsPrefix shape) decsTrace family]
  exact rp05_piop_branch_total_oracle_family piopFuel shape
    (stageOf decsTrace) enough (reply, piopTrace) decsFamily

end
end HegemonCrypto.SmallWood.Q38Rp05CurrentTrace
