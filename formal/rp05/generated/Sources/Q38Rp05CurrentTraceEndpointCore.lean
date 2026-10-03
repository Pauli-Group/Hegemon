import Q38Rp05CurrentTraceCore
import Q38Rp05OpenedOverlay
import SmzaRp05CurrentCoset406

/-! Minimal declaration-preserving home for the fixed-oracle staging and
selected-physical-overlay identities consumed by the direct privacy route.
It intentionally excludes the full trace-mass and oracle-trace analyses. -/
namespace HegemonCrypto.SmallWood.Q38Rp05CurrentTrace

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch (LeafIndex)
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame (SaltBytes)
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy (WitnessPackingValues)
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge (smz9LvcsSelectedBlockMap)
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.V8Smz9SingleProofPrivacy (lvcsPublicCombinationHeads)
open HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406 (evaluationPoint)
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra (Q D)
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport (rp05SourceLeafInput)
open HegemonCrypto.SmallWood.Q38Rp05CurrentPrefinal
open HegemonCrypto.SmallWood.Q38Rp05RequestCompiler (decsReply)
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.Q38Rp05OpenedOverlay
open HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy (updateRp05Batch)
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement (RelationDsl)
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open Hegemon.Transaction.Poseidon2V8RelationProgram
open scoped BigOperators Classical

local notation "Statement" =>
  HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement

noncomputable section
set_option autoImplicit false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

/-- At a fixed corrected SMZA oracle the DECS stage is evaluated first; its
actual answer determines D, and only then are the response-indexed PIOP
keys queried. Source coins remain correlated with that same oracle. -/
theorem current_prefinal_fixed_oracle_stage
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (salt : SaltBytes)
    (labels : LeafIndex → DigestRegister)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (oracle : Rp05OtherRawInput bound → DigestRegister) :
    let shape := rp05CurrentPrefinalShape bound largeEnough dsl statement
      salt labels widthBound
    let stage := NonleafProgram.interpret oracle (decsPrefix shape)
    let reply := decsReply values base masks stage.decsGamma
    NonleafProgram.interpret oracle
        (rp05CurrentPrefinal bound largeEnough dsl statement salt labels
          values base masks widthBound) =
      (NonleafProgram.interpret oracle (piopSuffix shape stage reply), reply) := by
  rw [current_prefinal_is_staged]
  simp only [NonleafProgram.interpret_bind, NonleafProgram.interpret]

/-- At the corrected physical-input type, the 38 programmed keys and values
of a successful opening are exactly the public q38-view keys and values.
This pure identity uses the actual 1,176-byte payload and changes no proof
carrier size; the accepted-DSL combination-head bridge is separate. -/
theorem current_selected_physical_overlay_eq_public
    (bound : Nat) (points : Fin 6 → Goldilocks)
    (injective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : Gamma Goldilocks)
    (heads : Heads Goldilocks) (tails : Tails Goldilocks)
    (decsMask : Decs Goldilocks)
    (selected : Fin 38 → LeafIndex)
    (distinct : Function.Injective selected)
    (statement : Statement) (salt : SaltBytes)
    (tapes : LeafIndex → LeafTape)
    (labels : Fin 38 → DigestRegister)
    (oracle : Rp05FullRawInput bound → DigestRegister) :
    updateRp05Batch 38 (fun opening : Fin 38 =>
      (Sum.inl (rp05SourceLeafInput statement salt
        (q38PhysicalSuffix heads tails decsMask (selected opening))
        (selected opening) (tapes (selected opening))) :
        Rp05FullRawInput bound)) labels oracle =
    updateRp05Batch 38 (fun opening : Fin 38 =>
      (Sum.inl (rp05SourceLeafInput statement salt
        (q38SelectedPublicData selected
          (q38PublicSuffix points injective gamma
            (V8SmzaMathPrivacy.response gamma heads tails decsMask)
            (lvcsPublicCombinationHeads points heads)
            (V8SmzaMathPrivacy.earlier points tails)
            (fun i => evaluationPoint (selected i))
            (fullSubset heads tails (fun i => evaluationPoint (selected i))))
          (selected opening))
        (selected opening) (tapes (selected opening))) :
        Rp05FullRawInput bound)) labels oracle := by
  have keysEq := q38_selected_physical_keys_eq_public
    (Other := Rp05OtherRawInput bound) points injective gamma heads tails
    decsMask selected distinct statement salt tapes
  exact congrArg
    (fun inputs : Fin 38 →
        HegemonCrypto.SmallWood.Q38Rp05LeafSupport.Rp05LeafInput ⊕
          Rp05OtherRawInput bound =>
      updateRp05Batch 38 inputs labels oracle) keysEq

end
end HegemonCrypto.SmallWood.Q38Rp05CurrentTrace
