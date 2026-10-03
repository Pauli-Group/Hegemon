import Q38Rp05CurrentTailDefinition
import Q38Rp05ExecutionBridgePointwise

/-!
# Current fixed-tape initialized overlay

This is the current RP05 key and complete request tail specialized from the
symbolic pointwise execution bridge. The large leaf count appears only in the
theorem application, where no list or finite function table is unfolded.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest

open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.Q38Rp05OpenedOverlay
open HegemonCrypto.SmallWood.V8SmzaCmsIndexedSwap
open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch (LeafIndex)
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame (SaltBytes)
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
open HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
open HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open Hegemon.Transaction.Poseidon2V8RelationProgram
open scoped Classical

local notation "Statement" =>
  HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

-- The polymorphic overlay theorem constructs the finite function space with
-- classical equality on its abstract environment. Use that same equality
-- dictionary here, so conversion does not compare two enumerations of the
-- 8,388,608-index function space. The finite set and uniform law are unchanged.
local instance tailLeafIndexDecidableEq : DecidableEq LeafIndex :=
  Classical.decEq LeafIndex

-- This leaf specializes an already checked execution identity. Its
-- interpreters and finite averages must remain symbolic during the final
-- identity-index simplification; unfolding them would enumerate the
-- concrete full-tree program instead of checking that specialization.
attribute [local irreducible] readCurrentAnswers updateRp05Batch
  compressedSwapList currentRequestTail liftEnvironmentProgram
  initializedPhaseFamily phaseRun uniformAverage
  V8Smz9HonestWholeViewGames.run

-- Keep the concrete site, key, and continuation maps opaque at the
-- 8,388,608-site theorem boundary. Their definitions are used only in the
-- small injectivity proof below; theorem application sees shared constants.
private def rp05CurrentTailSites : Fin 8388608 → LeafIndex := fun index =>
  ⟨index.val, by omega⟩

private def rp05CurrentTailKeys
    {bound : Nat} (statement : Statement) (salt : SaltBytes)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (tapes : LeafIndex → LeafTape) :
    LeafIndex → Rp05LeafInput ⊕ Rp05OtherRawInput bound :=
  fun index => Sum.inl (rp05SourceLeafInput statement salt
    (q38PhysicalSuffix (currentHeads values base masks.1)
      base.2.2 masks.2 index) index (tapes index))

private def rp05CurrentTailProgram
    {bound : Nat} {Work : Type} [Fintype Work]
    (largeEnough : 39162 ≤ bound) (dsl : RelationDsl)
    (statement : Statement) (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (tapes : LeafIndex → LeafTape)
    (next : Except String (List Byte) →
      Program (Rp05LeafInput ⊕ Rp05OtherRawInput bound) Work)
    (labels : Fin 8388608 → DigestRegister) :
    Program (Rp05LeafInput ⊕ Rp05OtherRawInput bound) Work :=
  currentRequestTail largeEnough dsl statement values salt widthBound
    base masks tapes labels next

attribute [local irreducible] rp05CurrentTailSites rp05CurrentTailKeys
  rp05CurrentTailProgram

/-- Eliminate identity reindexing while the read count is still symbolic.
The concrete specialization below therefore compares no full-tree recursor. -/
private theorem initialized_full_overlay_identity_sites
    {Other Work Environment : Type} [Fintype Other] [DecidableEq Other]
    [Fintype Work] [DecidableEq Work]
    [Fintype Environment]
    (count : Nat) (sites : Fin count → Environment)
    (siteDistinct : Function.Injective sites)
    (keys : Environment → Rp05LeafInput ⊕ Other)
    (distinct : Function.Injective (fun i => keys (sites i)))
    (family : OracleRegisterFamily
      (Input := Rp05LeafInput ⊕ Other) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (next : (Fin count → DigestRegister) →
      Program (Rp05LeafInput ⊕ Other) Work) :
    phaseRun true
        (liftEnvironmentProgram (Environment := Environment → DigestRegister)
          (readCurrentAnswers count (fun i => keys (sites i)) next))
        (compressedSwapList keys (List.ofFn sites)
          (initializedPhaseFamily family)) =
      uniformAverage (fun oldOracle : (Rp05LeafInput ⊕ Other) → DigestRegister =>
        uniformAverage (fun labels : Environment → DigestRegister =>
          let outputs := fun i => labels (sites i)
          V8Smz9HonestWholeViewGames.run true (next outputs)
            (updateRp05Batch count (fun i => keys (sites i)) outputs oldOracle)
            (familyGameState family oldOracle))) := by
  exact compressed_swaps_current_reads_eq_full_overlay_at
    (Other := Other) (Work := Work) (Environment := Environment)
    count sites siteDistinct keys distinct family next

/-- Symbolic-count endpoint for the complete current RP05 request tail.
The explicit count equality records the concrete full-leaf cardinality, while
the supplied equivalence transports only the finite index type. Keeping the
count symbolic here prevents `List.ofFn` from reducing an 8,388,608-element
list during theorem application. -/
theorem current_request_tail_initialized_full_overlay_at_pointwise_aligned
    {bound count : Nat} {Work : Type} [Fintype Work] [DecidableEq Work]
    (countEq : count = 8388608)
    (sites : Fin count ≃ LeafIndex)
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (tapes : LeafIndex → LeafTape)
    (next : Except String (List Byte) →
      Program (Rp05LeafInput ⊕ Rp05OtherRawInput bound) Work)
    (family : OracleRegisterFamily
      (Input := Rp05LeafInput ⊕ Rp05OtherRawInput bound)
      (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work)) :
    let keys := rp05CurrentTailKeys (bound := bound) statement salt
      values base masks tapes
    let continuation : (Fin count → DigestRegister) →
        Program (Rp05LeafInput ⊕ Rp05OtherRawInput bound) Work :=
      fun labels => currentRequestTail largeEnough dsl statement values salt
        widthBound base masks tapes (fun leaf => labels (sites.symm leaf)) next
    phaseRun true
        (liftEnvironmentProgram (Environment := LeafIndex → DigestRegister)
          (readCurrentAnswers count (fun i => keys (sites i)) continuation))
        (compressedSwapList keys (List.ofFn (sites : Fin count → LeafIndex))
          (initializedPhaseFamily family)) =
      uniformAverage (fun oldOracle :
          (Rp05LeafInput ⊕ Rp05OtherRawInput bound) → DigestRegister =>
        uniformAverage (fun labels : LeafIndex → DigestRegister =>
          let outputs := fun i => labels (sites i)
          V8Smz9HonestWholeViewGames.run true (continuation outputs)
          (updateRp05Batch count (fun i => keys (sites i)) outputs oldOracle)
            (familyGameState family oldOracle))) := by
  intro keys continuation
  have _countAligned : count = 8388608 := countEq
  have siteDistinct : Function.Injective (sites : Fin count → LeafIndex) :=
    sites.injective
  have sourceDistinct := rp05_source_inputs_distinct
    (Other := Rp05OtherRawInput bound) statement salt
    (q38PhysicalSuffix (currentHeads values base masks.1)
      base.2.2 masks.2) tapes
  have keyDistinct : Function.Injective (fun i : Fin count =>
      keys (sites i)) := by
    intro i j same
    have sourceSame :
        (Sum.inl (rp05SourceLeafInput statement salt
          (q38PhysicalSuffix (currentHeads values base masks.1)
            base.2.2 masks.2 (sites i))
          (sites i) (tapes (sites i))) :
            Rp05LeafInput ⊕ Rp05OtherRawInput bound) =
        (Sum.inl (rp05SourceLeafInput statement salt
          (q38PhysicalSuffix (currentHeads values base masks.1)
            base.2.2 masks.2 (sites j))
          (sites j) (tapes (sites j))) :
            Rp05LeafInput ⊕ Rp05OtherRawInput bound) := by
      simpa only [keys, rp05CurrentTailKeys] using same
    have indicesSame := sourceDistinct sourceSame
    have leafSame : sites i = sites j := indicesSame
    exact sites.injective leafSame
  exact @initialized_full_overlay_identity_sites
    (Rp05OtherRawInput bound) Work LeafIndex
    inferInstance inferInstance inferInstance inferInstance inferInstance
    count (sites : Fin count → LeafIndex) siteDistinct
    keys keyDistinct family continuation

end
end HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
