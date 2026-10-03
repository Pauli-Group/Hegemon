import Q38Rp05DependentP10
import Q38Rp05CurrentTraceEndpointCore
import Q38Rp05CurrentResultAverage

/-! Retained physical payload/byte identities for the actual recorded
current-profile request. Source only, not a kernel-checked endpoint. -/
namespace HegemonCrypto.SmallWood.Q38Rp05RetainedKernelJoin

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyComposition
open HegemonCrypto.SmallWood.V8Smz9HonestLeafBatch
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9HonestOpeningSchedule
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9EagerSimulator
open HegemonCrypto.SmallWood.V8Smz9AdjacentComposition
open HegemonCrypto.SmallWood.V8Smz9PrivacyGameComposition
open HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.V8SmzaLeafFrameHybrid
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy
open HegemonCrypto.SmallWood.Q38Rp05RequestCompiler
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05WholePrivacy
open HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler
open HegemonCrypto.SmallWood.Q38Rp05SelectedContinuation
open HegemonCrypto.SmallWood.Q38Rp05CurrentPrefinal
open HegemonCrypto.SmallWood.Q38Rp05CurrentPostfinal
open HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
open HegemonCrypto.SmallWood.Q38Rp05CurrentAdaptiveOpening
open HegemonCrypto.SmallWood.Q38Rp05CurrentP10
open HegemonCrypto.SmallWood.V8Smz9PostFinalProgram (certifyOpening)
open HegemonCrypto.SmallWood.Q38Rp05CurrentTrace
open HegemonCrypto.SmallWood.Q38Rp05OpeningSchedule
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38Rp05RecordedRequest
open HegemonCrypto.SmallWood.Q38Rp05DependentP10
open HegemonCrypto.SmallWood.Q38Rp05OpenedOverlay
open HegemonCrypto.SmallWood.Q38Rp05AdaptiveOpening
open HegemonCrypto.SmallWood.Q38Rp05FullAdaptiveComposition
open HegemonCrypto.SmallWood.Q38Rp05MaskRecovery
open HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
open HegemonCrypto.SmallWood.Q38Rp05NonleafComposition
open HegemonCrypto.SmallWood.SmzaRp05CsrNormalization
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open Hegemon.Transaction.Poseidon2V8RelationProgram
open scoped BigOperators Classical

set_option allowUnsafeReducibility true in
attribute [local reducible]
  HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge.piopOpeningCount
  HegemonCrypto.SmallWood.V8Smz9LogicalOracle.piopOpeningCount

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 0

local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte

private theorem recorded_physical_view_opened_oracle_none
    (bound : Nat) (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement) (opening : ComputedOpening)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (m : D)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (salt : SaltBytes) (tapes : TapeTable)
    (labels : LeafIndex → DigestRegister)
    (result : SelectionResult opening.points)
    (targetsNone : result.targets = none)
    (oldOracle : Rp05FullRawInput bound → DigestRegister) :
    currentPublicOpenedOracleFromResult bound dsl statement parameters opening
      gamma reply transcript salt tapes labels
      (selectedPhysicalView values base q reply result) result oldOracle =
    overlay (fun input => oldOracle (Sum.inl input))
      (fun input => oldOracle (Sum.inr input)) labels statement salt
      (q38PhysicalSuffix (currentHeads values base q) base.2.2 m)
      (rp05AbortAwareUnopened result)ᶜ tapes := by
  have viewNone :
      (selectedPhysicalView values base q reply result).2.2.2 = none := by
    simp only [selectedPhysicalView, targetsNone, Option.map_none]
  funext input
  cases input <;>
    simp [currentPublicOpenedOracleFromResult, targetsNone, viewNone,
      rp05AbortAwareUnopened, overlay, support]

private theorem recorded_physical_view_opened_oracle_some_selected_public_eq
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (bound : Nat) (statement : Statement)
    (parameters : Parameters
      (normalizedDsl components nonlinearRoot nodeDegree) statement)
    (opening : ComputedOpening)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (salt : SaltBytes) (tapes : TapeTable)
    (labels : LeafIndex → DigestRegister)
    (targets : HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler.IndexedTargets
      opening.points)
    (result : SelectionResult opening.points)
    (resultTargets : result.targets = some targets)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (selectedBatch : Rp05FullRawInput bound → DigestRegister)
    (selectedBatchDef : selectedBatch = updateRp05Batch 38
      (fun i : Fin 38 => Sum.inl (rp05SourceLeafInput statement salt
        (q38SelectedPublicData targets.val
          (q38PublicSuffix opening.points
            (computed_opening_selected_rank opening) gamma reply
            (combinationHeads (normalizedDsl components nonlinearRoot nodeDegree)
              statement parameters opening.points transcript
              (sourceWitnessOpenings values opening.points base.1)
              (sourcePcsFullView opening.points (pcsBase opening.points q reply)
                base.2.1))
            (earlier opening.points base.2.2)
            (fun i =>
              HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.evaluationPoint
                (targets.val i))
            (fullSubset (currentHeads values base q) base.2.2
              (fun i =>
                HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.evaluationPoint
                  (targets.val i))))
          (targets.val i))
        (targets.val i) (tapes (targets.val i))))
      (fun i => labels (targets.val i)) oldOracle) :
    currentPublicOpenedOracleFromResult bound
      (normalizedDsl components nonlinearRoot nodeDegree) statement parameters
      opening gamma reply transcript salt tapes labels
      (selectedPhysicalView values base q reply result) result oldOracle =
    selectedBatch := by
  have viewLater :
      (selectedPhysicalView values base q reply result).2.2.2 =
        some (fullSubset (currentHeads values base q) base.2.2
          (indexedPoints targets.val)) := by
    simp only [selectedPhysicalView, resultTargets, Option.map_some]
  have selectedIndicesEq : selectedIndices result = targets.val := by
    simp only [selectedIndices, resultTargets]
  rw [selectedBatchDef]
  simp only [currentPublicOpenedOracleFromResult, resultTargets, viewLater,
    selectedIndicesEq]
  rfl

private theorem recorded_physical_view_combination_heads_transport
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (points : Fin 6 → Goldilocks)
    (leftTranscript rightTranscript : Q)
    (witness : WitnessOpeningView Goldilocks)
    (leftPcs rightPcs : SourcePcsView Goldilocks)
    (expected : PublicCombinationHeads Goldilocks)
    (transcriptEq : leftTranscript = rightTranscript)
    (pcsEq : leftPcs = rightPcs)
    (knownHeads : combinationHeads dsl statement parameters points
      rightTranscript witness rightPcs = expected) :
    combinationHeads dsl statement parameters points leftTranscript witness
      leftPcs = expected := by
  exact
    (congrArg₂
      (fun transcript pcs =>
        combinationHeads dsl statement parameters points transcript witness pcs)
      transcriptEq pcsEq).trans knownHeads

private theorem pcsBase_reply_independent
    (points : Fin 6 → Goldilocks) (q : Q) (reply : D) :
    pcsBase points q reply = pcsBase points q 0 := rfl

private theorem recorded_physical_view_opened_oracle_some_heads_eq
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates
      (normalizedDsl components nonlinearRoot nodeDegree))
    (statement : Statement)
    (parameters : Parameters
      (normalizedDsl components nonlinearRoot nodeDegree) statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (reply : D)
    (transcript : Q)
    (transcriptEq : transcript =
      Q38Rp05ChronologicalAlgebra.response
        (normalizedDsl components nonlinearRoot nodeDegree) statement parameters
        (sourceWitnessPolynomials values base.1) q)
    (opening : ComputedOpening)
    (accepted : components.AcceptsPacked (currentPublicWords statement)
      (rp05PackValues values)) :
    combinationHeads (normalizedDsl components nonlinearRoot nodeDegree)
      statement parameters opening.points transcript
      (sourceWitnessOpenings values opening.points base.1)
      (sourcePcsFullView opening.points
        (pcsBase opening.points q reply) base.2.1) =
      HegemonCrypto.SmallWood.V8Smz9SingleProofPrivacy.lvcsPublicCombinationHeads
        opening.points (currentHeads values base q) := by
  have pcsEq :
      sourcePcsFullView opening.points (pcsBase opening.points q reply)
        base.2.1 =
      sourcePcsFullView opening.points (pcsBase opening.points q 0)
        base.2.1 :=
    congrArg (fun pcs => sourcePcsFullView opening.points pcs base.2.1)
      (pcsBase_reply_independent opening.points q reply)
  exact recorded_physical_view_combination_heads_transport
    (normalizedDsl components nonlinearRoot nodeDegree) statement parameters
    opening.points transcript
    (Q38Rp05ChronologicalAlgebra.response
      (normalizedDsl components nonlinearRoot nodeDegree) statement parameters
      (sourceWitnessPolynomials values base.1) q)
    (sourceWitnessOpenings values opening.points base.1)
    (sourcePcsFullView opening.points (pcsBase opening.points q reply)
      base.2.1)
    (sourcePcsFullView opening.points (pcsBase opening.points q 0) base.2.1)
    (HegemonCrypto.SmallWood.V8Smz9SingleProofPrivacy.lvcsPublicCombinationHeads
      opening.points (currentHeads values base q))
    transcriptEq pcsEq
    (rp05_accepted_combination_heads_are_physical
      components nonlinearRoot nodeDegree certificates statement parameters
      opening.points (computed_opening_interpolation_admissible opening)
      values base.1 q base.2.1 accepted)

private theorem recorded_physical_view_opened_oracle_some_selected_batch_eq_physical
    (dsl : RelationDsl)
    (bound : Nat) (statement : Statement)
    (parameters : Parameters dsl statement)
    (opening : ComputedOpening)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (m : D)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (replyEq : reply = V8SmzaMathPrivacy.response gamma
      (currentHeads values base q) base.2.2 m)
    (headsEq : combinationHeads dsl statement parameters opening.points transcript
      (sourceWitnessOpenings values opening.points base.1)
      (sourcePcsFullView opening.points
        (pcsBase opening.points q reply) base.2.1) =
      HegemonCrypto.SmallWood.V8Smz9SingleProofPrivacy.lvcsPublicCombinationHeads
        opening.points (currentHeads values base q))
    (salt : SaltBytes) (tapes : TapeTable)
    (labels : LeafIndex → DigestRegister)
    (targets : HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler.IndexedTargets
      opening.points)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (selectedBatch : Rp05FullRawInput bound → DigestRegister)
    (selectedBatchDef : selectedBatch = updateRp05Batch 38
      (fun i : Fin 38 => Sum.inl (rp05SourceLeafInput statement salt
        (q38SelectedPublicData targets.val
          (q38PublicSuffix opening.points
            (computed_opening_selected_rank opening) gamma reply
            (combinationHeads dsl
              statement parameters opening.points transcript
              (sourceWitnessOpenings values opening.points base.1)
              (sourcePcsFullView opening.points (pcsBase opening.points q reply)
                base.2.1))
            (earlier opening.points base.2.2)
            (fun i =>
              HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.evaluationPoint
                (targets.val i))
            (fullSubset (currentHeads values base q) base.2.2
              (fun i =>
                HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.evaluationPoint
                  (targets.val i))))
          (targets.val i))
        (targets.val i) (tapes (targets.val i))))
      (fun i => labels (targets.val i)) oldOracle)
    (physicalBatch : Rp05FullRawInput bound → DigestRegister)
    (physicalBatchDef : physicalBatch = updateRp05Batch 38
      (fun i : Fin 38 => Sum.inl (rp05SourceLeafInput statement salt
        (q38PhysicalSuffix (currentHeads values base q) base.2.2 m
          (targets.val i))
        (targets.val i) (tapes (targets.val i))))
      (fun i => labels (targets.val i)) oldOracle) :
    selectedBatch = physicalBatch := by
  have physical := current_selected_physical_overlay_eq_public bound
    opening.points (computed_opening_selected_rank opening) gamma
    (currentHeads values base q) base.2.2 m targets.val targets.property.1
    statement salt tapes (fun i => labels (targets.val i)) oldOracle
  rw [selectedBatchDef, physicalBatchDef]
  rw [headsEq]
  rw [replyEq]
  exact physical.symm

private theorem recorded_physical_view_opened_oracle_some_physical_batch_eq_overlay
    (bound : Nat) (statement : Statement) (opening : ComputedOpening)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (m : D)
    (salt : SaltBytes) (tapes : TapeTable)
    (labels : LeafIndex → DigestRegister)
    (targets : HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler.IndexedTargets
      opening.points)
    (result : SelectionResult opening.points)
    (resultTargets : result.targets = some targets)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (physicalBatch : Rp05FullRawInput bound → DigestRegister)
    (physicalBatchDef : physicalBatch = updateRp05Batch 38
      (fun i : Fin 38 => Sum.inl (rp05SourceLeafInput statement salt
        (q38PhysicalSuffix (currentHeads values base q) base.2.2 m
          (targets.val i))
        (targets.val i) (tapes (targets.val i))))
      (fun i => labels (targets.val i)) oldOracle) :
    physicalBatch =
      overlay (fun input => oldOracle (Sum.inl input))
        (fun input => oldOracle (Sum.inr input)) labels statement salt
        (q38PhysicalSuffix (currentHeads values base q) base.2.2 m)
        (rp05AbortAwareUnopened result)ᶜ tapes := by
  have unopenedEq : rp05AbortAwareUnopened result = q38Unopened targets.val := by
    simp [rp05AbortAwareUnopened, resultTargets]
  rw [physicalBatchDef, unopenedEq]
  exact (current_opened_overlay_eq_batch bound statement salt
    (q38PhysicalSuffix (currentHeads values base q) base.2.2 m)
    targets.val targets.property.1 labels tapes oldOracle).symm

private theorem recorded_physical_view_opened_oracle_some
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates
      (normalizedDsl components nonlinearRoot nodeDegree))
    (bound : Nat) (statement : Statement)
    (parameters : Parameters
      (normalizedDsl components nonlinearRoot nodeDegree) statement)
    (opening : ComputedOpening)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (m : D)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (replyEq : reply = V8SmzaMathPrivacy.response gamma
      (currentHeads values base q) base.2.2 m)
    (transcriptEq : transcript =
      Q38Rp05ChronologicalAlgebra.response
        (normalizedDsl components nonlinearRoot nodeDegree) statement parameters
        (sourceWitnessPolynomials values base.1) q)
    (salt : SaltBytes) (tapes : TapeTable)
    (labels : LeafIndex → DigestRegister)
    (targets : HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler.IndexedTargets
      opening.points)
    (result : SelectionResult opening.points)
    (resultTargets : result.targets = some targets)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (accepted : components.AcceptsPacked (currentPublicWords statement)
      (rp05PackValues values)) :
    currentPublicOpenedOracleFromResult bound
      (normalizedDsl components nonlinearRoot nodeDegree) statement parameters
      opening gamma reply transcript salt tapes labels
      (selectedPhysicalView values base q reply result) result oldOracle =
    overlay (fun input => oldOracle (Sum.inl input))
      (fun input => oldOracle (Sum.inr input)) labels statement salt
      (q38PhysicalSuffix (currentHeads values base q) base.2.2 m)
      (rp05AbortAwareUnopened result)ᶜ tapes := by
  let selectedBatch :=
    updateRp05Batch 38
      (fun i : Fin 38 => Sum.inl (rp05SourceLeafInput statement salt
        (q38SelectedPublicData targets.val
          (q38PublicSuffix opening.points
            (computed_opening_selected_rank opening) gamma reply
            (combinationHeads (normalizedDsl components nonlinearRoot nodeDegree)
              statement parameters opening.points transcript
              (sourceWitnessOpenings values opening.points base.1)
              (sourcePcsFullView opening.points (pcsBase opening.points q reply)
                base.2.1))
            (earlier opening.points base.2.2)
            (fun i =>
              HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.evaluationPoint
                (targets.val i))
            (fullSubset (currentHeads values base q) base.2.2
              (fun i =>
                HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.evaluationPoint
                  (targets.val i))))
          (targets.val i))
        (targets.val i) (tapes (targets.val i))))
      (fun i => labels (targets.val i)) oldOracle
  let physicalBatch :=
    updateRp05Batch 38
      (fun i : Fin 38 => Sum.inl (rp05SourceLeafInput statement salt
        (q38PhysicalSuffix (currentHeads values base q) base.2.2 m
          (targets.val i))
        (targets.val i) (tapes (targets.val i))))
      (fun i => labels (targets.val i)) oldOracle
  have selectedPublicEq :=
    recorded_physical_view_opened_oracle_some_selected_public_eq
      components nonlinearRoot nodeDegree bound statement parameters opening
      values base q gamma reply transcript salt tapes labels targets result
      resultTargets oldOracle selectedBatch rfl
  have headsEq :=
    recorded_physical_view_opened_oracle_some_heads_eq
      components nonlinearRoot nodeDegree certificates statement parameters
      values base q reply transcript transcriptEq opening accepted
  have selectedBatchEqPhysicalBatch :=
    recorded_physical_view_opened_oracle_some_selected_batch_eq_physical
      (normalizedDsl components nonlinearRoot nodeDegree) bound statement
      parameters opening values base q m gamma reply transcript replyEq headsEq
      salt tapes labels targets oldOracle
      selectedBatch rfl physicalBatch rfl
  have physicalBatchEqOverlay :=
    recorded_physical_view_opened_oracle_some_physical_batch_eq_overlay
      bound statement opening values base q m salt tapes labels targets result
      resultTargets oldOracle physicalBatch rfl
  exact @Eq.trans (Rp05FullRawInput bound → DigestRegister)
    (currentPublicOpenedOracleFromResult bound
      (normalizedDsl components nonlinearRoot nodeDegree) statement parameters
      opening gamma reply transcript salt tapes labels
      (selectedPhysicalView values base q reply result) result oldOracle)
    selectedBatch
    (overlay (fun input => oldOracle (Sum.inl input))
      (fun input => oldOracle (Sum.inr input)) labels statement salt
      (q38PhysicalSuffix (currentHeads values base q) base.2.2 m)
      (rp05AbortAwareUnopened result)ᶜ tapes)
    selectedPublicEq
    (@Eq.trans (Rp05FullRawInput bound → DigestRegister)
      selectedBatch physicalBatch
      (overlay (fun input => oldOracle (Sum.inl input))
        (fun input => oldOracle (Sum.inr input)) labels statement salt
        (q38PhysicalSuffix (currentHeads values base q) base.2.2 m)
        (rp05AbortAwareUnopened result)ᶜ tapes)
      selectedBatchEqPhysicalBatch physicalBatchEqOverlay)

private theorem recorded_physical_view_opened_oracle_dispatch
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates
      (normalizedDsl components nonlinearRoot nodeDegree))
    (bound : Nat) (statement : Statement)
    (parameters : Parameters
      (normalizedDsl components nonlinearRoot nodeDegree) statement)
    (opening : ComputedOpening)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (m : D)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (replyEq : reply = V8SmzaMathPrivacy.response gamma
      (currentHeads values base q) base.2.2 m)
    (transcriptEq : transcript =
      Q38Rp05ChronologicalAlgebra.response
        (normalizedDsl components nonlinearRoot nodeDegree) statement parameters
        (sourceWitnessPolynomials values base.1) q)
    (salt : SaltBytes) (tapes : TapeTable)
    (labels : LeafIndex → DigestRegister)
    (result : SelectionResult opening.points)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (accepted : components.AcceptsPacked (currentPublicWords statement)
      (rp05PackValues values)) :
    currentPublicOpenedOracleFromResult bound
        (normalizedDsl components nonlinearRoot nodeDegree) statement parameters
        opening gamma reply transcript salt tapes labels
        (selectedPhysicalView values base q reply result) result oldOracle =
      overlay (fun input => oldOracle (Sum.inl input))
        (fun input => oldOracle (Sum.inr input)) labels statement salt
        (q38PhysicalSuffix (currentHeads values base q) base.2.2 m)
        (rp05AbortAwareUnopened result)ᶜ tapes := by
  by_cases noneTargets : result.targets = none
  · exact recorded_physical_view_opened_oracle_none
      bound (normalizedDsl components nonlinearRoot nodeDegree) statement
      parameters opening values base q m gamma reply transcript salt tapes
      labels result noneTargets oldOracle
  · obtain ⟨targets, resultTargets⟩ :=
      Option.ne_none_iff_exists'.mp noneTargets
    exact recorded_physical_view_opened_oracle_some
      components nonlinearRoot nodeDegree certificates bound statement
      parameters opening values base q m gamma reply transcript replyEq
      transcriptEq salt tapes
      labels targets result resultTargets oldOracle accepted

/-- The record may be ANY genuine indexed result, including exhaustion.
No oracle alignment or repeated-selector premise is needed: the physical
view and public constructor consume exactly that supplied result. -/
theorem recorded_physical_view_opened_oracle
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates
      (normalizedDsl components nonlinearRoot nodeDegree))
    (bound : Nat) (statement : Statement)
    (parameters : Parameters
      (normalizedDsl components nonlinearRoot nodeDegree) statement)
    (opening : ComputedOpening)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (m : D)
    (gamma : Gamma Goldilocks) (salt : SaltBytes)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (result : SelectionResult opening.points)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (accepted : components.AcceptsPacked (currentPublicWords statement)
      (rp05PackValues values)) :
    let reply := V8SmzaMathPrivacy.response gamma
      (currentHeads values base q) base.2.2 m
    let transcript := Q38Rp05ChronologicalAlgebra.response
      (normalizedDsl components nonlinearRoot nodeDegree) statement parameters
      (sourceWitnessPolynomials values base.1) q
    currentPublicOpenedOracleFromResult bound
        (normalizedDsl components nonlinearRoot nodeDegree) statement parameters
        opening gamma reply transcript salt tapes labels
        (selectedPhysicalView values base q reply result) result oldOracle =
      overlay (fun input => oldOracle (Sum.inl input))
        (fun input => oldOracle (Sum.inr input)) labels statement salt
        (q38PhysicalSuffix (currentHeads values base q) base.2.2 m)
        (rp05AbortAwareUnopened result)ᶜ tapes := by
  exact recorded_physical_view_opened_oracle_dispatch
    components nonlinearRoot nodeDegree certificates bound statement parameters
    opening values base q m gamma
    (V8SmzaMathPrivacy.response gamma (currentHeads values base q) base.2.2 m)
    (Q38Rp05ChronologicalAlgebra.response
      (normalizedDsl components nonlinearRoot nodeDegree) statement parameters
      (sourceWitnessPolynomials values base.1) q)
    rfl rfl
    salt tapes labels result oldOracle accepted

private theorem piop_suffix_decs_gamma
    {Other : Type} (shape : Q38PrefinalShape Other)
    (oracle : Other → DigestRegister) (stage : DecsStage)
    (reply : Q38DecsResponse) :
    (NonleafProgram.interpret oracle
      (piopSuffix shape stage reply)).decsGamma = stage.decsGamma := by
  simp only [piopSuffix, NonleafProgram.interpret_bind,
    NonleafProgram.interpret]

/-- All actual D-indexed PIOP outcomes retain exactly the DECS matrix from
their own prefix, even when either source sampler exhausts. -/
theorem dynamic_stage_gamma
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (salt : SaltBytes)
    (labels : LeafIndex → DigestRegister)
    (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (oracle : Rp05OtherRawInput bound → DigestRegister) (reply : D) :
    (dynamicStage largeEnough dsl statement salt labels widthBound oracle reply).gamma =
      decodedQ38DecsGamma (NonleafProgram.interpret oracle
        (decsPrefix (rp05CurrentPrefinalShape bound largeEnough dsl statement
          salt labels widthBound))).decsGamma := by
  let shape := rp05CurrentPrefinalShape bound largeEnough dsl statement
    salt labels widthBound
  let stage := NonleafProgram.interpret oracle (decsPrefix shape)
  change decodedQ38DecsGamma
      (NonleafProgram.interpret oracle (piopSuffix shape stage reply)).decsGamma =
    decodedQ38DecsGamma stage.decsGamma
  exact congrArg decodedQ38DecsGamma
    (piop_suffix_decs_gamma shape oracle stage reply)

/-- The nondependent source-view constructor for one abstract opening result.
The actual dynamic view below supplies the interpreter's recorded opening. -/
private def dynamicSourceViewCore
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q)
    (abortPoints : Fin 6 → Goldilocks)
    (stage : DynamicStage dsl statement)
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (reply : D) (transcript : Q) (digest : DigestRegister)
    (opening : Option ComputedOpening) : PartialView Goldilocks :=
  let points := dynamicPoints abortPoints opening
  partialChronologicalView values points
    (fun _ => pcsBase points q reply)
    (fun witness pcs =>
      currentPhysicalHeadsView values witness q pcs)
    (dynamicChooseCore largeEnough dsl statement abortPoints stage oracle transcript
      digest opening) base

private theorem dynamicSourceViewCore_some_eq_recorded_result
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (reply : D)
    (abortPoints : Fin 6 → Goldilocks)
    (stage : DynamicStage dsl statement)
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (transcript : Q) (digest : DigestRegister)
    (opening : ComputedOpening) :
    dynamicSourceViewCore largeEnough dsl statement values base q abortPoints
      stage oracle reply transcript digest (some opening) =
    selectedPhysicalView values base q reply
      (NonleafProgram.interpret oracle
        (currentSelectIndices bound largeEnough opening.points
          (computed_opening_points_distinct opening) digest
          (combinationHeads dsl statement stage.parameters opening.points transcript
            (sourceWitnessOpenings values opening.points base.1)
            (sourcePcsFullView opening.points (pcsBase opening.points q reply)
              base.2.1))
          (earlier opening.points base.2.2) opening.pendingFailure)) := by
  simpa only [dynamicSourceViewCore, dynamicPoints, dynamicChooseCore,
    currentPhysicalHeadsView] using
    current_partial_view_eq_recorded_result bound largeEnough dsl statement
      stage.parameters opening values base q reply transcript digest oracle

/-- Source view in the actual D -> PIOP -> S -> nonce chronology. On nonce
abort its fallback coordinates are ignored by the observable continuation. -/
def dynamicSourceView
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q)
    (abortPoints : Fin 6 → Goldilocks)
    (stage : DynamicStage dsl statement)
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (reply : D) (transcript : Q) : PartialView Goldilocks :=
  dynamicSourceViewCore largeEnough dsl statement values base q abortPoints
    stage oracle reply transcript (dynamicDigest largeEnough stage oracle transcript)
    (dynamicOpening largeEnough stage oracle transcript)

/-- Physical retained observation from the already-computed public stage.
The only remaining queries are those of `next`; nonce/index execution here
is a fixed-oracle denotation of the one actual recorded prefix. -/
private def stagedPhysicalObservationCore
    {bound : Nat} {Work : Type} [Fintype Work]
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (m : D)
    (salt : SaltBytes) (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (stage : DynamicStage dsl statement)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work))
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work)
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (reply : D) (transcript : Q) (digest : DigestRegister)
    (opening : Option ComputedOpening) : ℝ :=
  match opening with
  | none => run true (next (.error "smallwood opening nonce trial limit exhausted"))
      oldOracle state
  | some opening =>
    let selected := NonleafProgram.interpret oracle
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest
        (combinationHeads dsl statement stage.parameters opening.points transcript
          (sourceWitnessOpenings values opening.points base.1)
          (sourcePcsFullView opening.points (pcsBase opening.points q reply) base.2.1))
        (earlier opening.points base.2.2) opening.pendingFailure)
    run true (next (selectedBytes dsl statement stage.parameters opening stage.gamma
        reply transcript digest salt stage.tree tapes
        (selectedPhysicalView values base q reply selected) selected))
      (overlay (fun input => oldOracle (Sum.inl input)) oracle labels statement salt
        (q38PhysicalSuffix (currentHeads values base q) base.2.2 m)
        (rp05AbortAwareUnopened selected)ᶜ tapes) state

/-- Physical retained observation from the already-computed public stage.
The only remaining queries are those of `next`; nonce/index execution here
is a fixed-oracle denotation of the one actual recorded prefix. -/
def stagedPhysicalObservation
    {bound : Nat} {Work : Type} [Fintype Work]
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (m : D)
    (salt : SaltBytes) (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (stage : DynamicStage dsl statement)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work))
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work) : ℝ :=
  let oracle := fun input => oldOracle (Sum.inr input)
  let reply := V8SmzaMathPrivacy.response stage.gamma
    (currentHeads values base q) base.2.2 m
  let transcript := Q38Rp05ChronologicalAlgebra.response dsl statement
    stage.parameters (sourceWitnessPolynomials values base.1) q
  let digest := dynamicDigest largeEnough stage oracle transcript
  stagedPhysicalObservationCore largeEnough dsl statement values base q m salt tapes
    labels stage oldOracle state next oracle reply transcript digest
    (dynamicOpening largeEnough stage oracle transcript)

private theorem dynamicKernel_nonce_abort_eq_observe
    {bound : Nat} {Value : Type*}
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (salt : SaltBytes) (tapes : TapeTable)
    (stage : DynamicStage dsl statement)
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (reply : D) (transcript : Q)
    (view : PartialView Goldilocks)
    (observe : RequestRecord dsl statement → PartialView Goldilocks →
      Except String (List Byte) → Value)
    (opened : dynamicOpening largeEnough stage oracle transcript = none) :
    dynamicKernel largeEnough dsl statement salt tapes stage oracle reply transcript view
      observe =
    observe ⟨stage.parameters, stage.gamma, reply, transcript,
      dynamicDigest largeEnough stage oracle transcript, stage.tree, .nonceAbort⟩
      view (.error "smallwood opening nonce trial limit exhausted") := by
  simp only [dynamicKernel, opened]

private theorem dynamicContinuationObservation_nonce_abort_eq_run
    {bound : Nat} {Work : Type} [Fintype Work]
    (dsl : RelationDsl) (statement : Statement)
    (salt : SaltBytes) (tapes : TapeTable)
    (labels : LeafIndex → DigestRegister)
    (stage : DynamicStage dsl statement)
    (digest : DigestRegister)
    (reply : D) (transcript : Q)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work))
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work)
    (view : PartialView Goldilocks) :
    dynamicContinuationObservation dsl statement salt tapes labels oldOracle state next
      ⟨stage.parameters, stage.gamma, reply, transcript,
        digest, stage.tree, .nonceAbort⟩ view
      (.error "smallwood opening nonce trial limit exhausted") =
    run true (next (.error "smallwood opening nonce trial limit exhausted"))
      oldOracle state := by
  simp only [dynamicContinuationObservation]
  exact congrArg
    (fun currentOracle =>
      run true (next (.error "smallwood opening nonce trial limit exhausted"))
        currentOracle state)
    (current_recorded_postfinal_nonce_abort_no_write bound dsl statement
      stage.parameters stage.gamma reply transcript salt tapes labels view oldOracle)

private theorem staged_physical_observation_eq_dynamic_kernel_of_oracle
    {bound : Nat} {Work : Type} [Fintype Work]
    (largeEnough : 39162 ≤ bound) (dsl : RelationDsl)
    (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (m : D)
    (abortPoints : Fin 6 → Goldilocks)
    (salt : SaltBytes) (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (stage : DynamicStage dsl statement)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work))
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work)
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (reply : D) (transcript : Q)
    (openedOracleEq : ∀ (opening : ComputedOpening)
      (result : SelectionResult opening.points),
      currentPublicOpenedOracleFromResult bound dsl statement stage.parameters
        opening stage.gamma reply transcript
        salt tapes labels
        (selectedPhysicalView values base q
          reply result)
      result oldOracle =
      overlay (fun input => oldOracle (Sum.inl input))
        oracle labels statement salt
        (q38PhysicalSuffix (currentHeads values base q) base.2.2 m)
        (rp05AbortAwareUnopened result)ᶜ tapes) :
    stagedPhysicalObservationCore largeEnough dsl statement values base q m salt tapes
        labels stage oldOracle state next oracle reply transcript
        (dynamicDigest largeEnough stage oracle transcript)
        (dynamicOpening largeEnough stage oracle transcript) =
      dynamicKernel largeEnough dsl statement salt tapes stage oracle reply transcript
        (dynamicSourceViewCore largeEnough dsl statement values base q abortPoints
          stage oracle reply transcript (dynamicDigest largeEnough stage oracle transcript)
          (dynamicOpening largeEnough stage oracle transcript))
        (dynamicContinuationObservation dsl statement salt tapes labels oldOracle
          state next) := by
  let digest := dynamicDigest largeEnough stage oracle transcript
  by_cases openedNone : dynamicOpening largeEnough stage oracle transcript = none
  ·
    have stagedEq :
        stagedPhysicalObservationCore largeEnough dsl statement values base q m salt
          tapes labels stage oldOracle state next oracle reply transcript digest
          (dynamicOpening largeEnough stage oracle transcript) =
        run true (next (.error "smallwood opening nonce trial limit exhausted"))
          oldOracle state := by
      exact (congrArg
        (stagedPhysicalObservationCore largeEnough dsl statement values base q m
          salt tapes labels stage oldOracle state next oracle reply transcript digest)
        openedNone).trans rfl
    let view : PartialView Goldilocks :=
      dynamicSourceViewCore largeEnough dsl statement values base q abortPoints
        stage oracle reply transcript digest
        (dynamicOpening largeEnough stage oracle transcript)
    let abort : Except String (List Byte) :=
      .error "smallwood opening nonce trial limit exhausted"
    let abortRecord : RequestRecord dsl statement :=
      ⟨stage.parameters, stage.gamma, reply, transcript, digest, stage.tree, .nonceAbort⟩
    let observe : RequestRecord dsl statement → PartialView Goldilocks →
        Except String (List Byte) → ℝ :=
      dynamicContinuationObservation dsl statement salt tapes labels oldOracle state next
    have kernelEq := dynamicKernel_nonce_abort_eq_observe largeEnough dsl statement
      salt tapes stage oracle reply transcript view observe openedNone
    have observeEq := dynamicContinuationObservation_nonce_abort_eq_run
      dsl statement salt tapes labels stage digest reply transcript
      oldOracle state next view
    calc
      stagedPhysicalObservationCore largeEnough dsl statement values base q m salt tapes
          labels stage oldOracle state next oracle reply transcript digest
          (dynamicOpening largeEnough stage oracle transcript) =
        run true (next abort) oldOracle state := stagedEq
      _ = observe abortRecord view abort := observeEq.symm
      _ = dynamicKernel largeEnough dsl statement salt tapes stage oracle reply transcript
          view observe := kernelEq.symm
  ·
    obtain ⟨opening, openedSome⟩ :=
      Option.ne_none_iff_exists'.mp openedNone
    let selected := NonleafProgram.interpret oracle
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest
        (combinationHeads dsl statement stage.parameters opening.points transcript
          (sourceWitnessOpenings values opening.points base.1)
          (sourcePcsFullView opening.points (pcsBase opening.points q reply) base.2.1))
        (earlier opening.points base.2.2) opening.pendingFailure)
    have viewEq : dynamicSourceViewCore largeEnough dsl statement values base q
        abortPoints stage oracle reply transcript digest
          (dynamicOpening largeEnough stage oracle transcript) =
        selectedPhysicalView values base q reply selected := by
      have coreOpenedEq := congrArg
        (dynamicSourceViewCore largeEnough dsl statement values base q abortPoints
          stage oracle reply transcript digest)
        openedSome
      exact coreOpenedEq.trans
        (dynamicSourceViewCore_some_eq_recorded_result largeEnough dsl statement
          values base q reply abortPoints stage oracle transcript digest opening)
    have oracleEq := openedOracleEq opening selected
    let observe : RequestRecord dsl statement → PartialView Goldilocks →
        Except String (List Byte) → ℝ :=
      dynamicContinuationObservation dsl statement salt tapes labels oldOracle state next
    have kernelViewEq :
        dynamicKernel largeEnough dsl statement salt tapes stage oracle reply transcript
          (dynamicSourceViewCore largeEnough dsl statement values base q abortPoints
            stage oracle reply transcript digest
            (dynamicOpening largeEnough stage oracle transcript)) observe =
        dynamicKernel largeEnough dsl statement salt tapes stage oracle reply transcript
          (selectedPhysicalView values base q reply selected) observe :=
      congrArg
        (fun view =>
          dynamicKernel largeEnough dsl statement salt tapes stage oracle reply transcript
            view observe)
        viewEq
    have physicalEq :
        stagedPhysicalObservationCore largeEnough dsl statement values base q m salt
          tapes labels stage oldOracle state next oracle reply transcript digest
          (dynamicOpening largeEnough stage oracle transcript) =
        dynamicKernel largeEnough dsl statement salt tapes stage oracle reply transcript
          (selectedPhysicalView values base q reply selected) observe := by
      have coreOpenedEq := congrArg
        (stagedPhysicalObservationCore largeEnough dsl statement values base q m
          salt tapes labels stage oldOracle state next oracle reply transcript digest)
        openedSome
      have coreSomeEq :
          stagedPhysicalObservationCore largeEnough dsl statement values base q m salt
            tapes labels stage oldOracle state next oracle reply transcript digest
            (some opening) =
          dynamicKernel largeEnough dsl statement salt tapes stage oracle reply transcript
            (selectedPhysicalView values base q reply selected) observe := by
        simp only [stagedPhysicalObservationCore, dynamicKernel, openedSome,
          observe, selectedPhysicalView, dynamicContinuationObservation,
          currentPublicOpenedOracleFromRecorded]
        exact congrArg₂
          (fun (bytes : Except String (List Byte))
              (currentOracle : Rp05FullRawInput bound → DigestRegister) =>
            run true (next bytes) currentOracle state)
          rfl oracleEq.symm
      exact coreOpenedEq.trans coreSomeEq
    calc
      stagedPhysicalObservationCore largeEnough dsl statement values base q m salt tapes
          labels stage oldOracle state next oracle reply transcript digest
          (dynamicOpening largeEnough stage oracle transcript) =
        dynamicKernel largeEnough dsl statement salt tapes stage oracle reply transcript
          (selectedPhysicalView values base q reply selected) observe := physicalEq
      _ = dynamicKernel largeEnough dsl statement salt tapes stage oracle reply transcript
          (dynamicSourceViewCore largeEnough dsl statement values base q abortPoints
            stage oracle reply transcript digest
            (dynamicOpening largeEnough stage oracle transcript)) observe := kernelViewEq.symm

/-- The actual physical retained bytes AND oracle equal the dependent P10
kernel, including both aborts, on the unchanged old-H state. Its only
semantic premises are accepted current-DSL constraints and their finite
certificates; no game identity or privacy inequality is assumed. -/
theorem staged_physical_observation_eq_dynamic_kernel
    {bound : Nat} {Work : Type} [Fintype Work]
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates
      (normalizedDsl components nonlinearRoot nodeDegree))
    (largeEnough : 39162 ≤ bound) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (m : D)
    (abortPoints : Fin 6 → Goldilocks)
    (salt : SaltBytes) (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (stage : DynamicStage (normalizedDsl components nonlinearRoot nodeDegree) statement)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work))
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work)
    (accepted : components.AcceptsPacked (currentPublicWords statement)
      (rp05PackValues values)) :
    let dsl := normalizedDsl components nonlinearRoot nodeDegree
    let oracle := fun input => oldOracle (Sum.inr input)
    let reply := V8SmzaMathPrivacy.response stage.gamma
      (currentHeads values base q) base.2.2 m
    let transcript := Q38Rp05ChronologicalAlgebra.response dsl statement
      stage.parameters (sourceWitnessPolynomials values base.1) q
    stagedPhysicalObservation largeEnough dsl statement values base q m salt tapes
        labels stage oldOracle state next =
      dynamicKernel largeEnough dsl statement salt tapes stage oracle reply transcript
        (dynamicSourceView largeEnough dsl statement values base q abortPoints
          stage oracle reply transcript)
        (dynamicContinuationObservation dsl statement salt tapes labels oldOracle
          state next) := by
  exact staged_physical_observation_eq_dynamic_kernel_of_oracle
    (bound := bound) (Work := Work) (largeEnough := largeEnough)
    (dsl := normalizedDsl components nonlinearRoot nodeDegree)
    (statement := statement) (values := values) (base := base)
    (q := q) (m := m) (abortPoints := abortPoints)
    (salt := salt) (tapes := tapes) (labels := labels)
    (stage := stage) (oldOracle := oldOracle) (state := state) (next := next)
    (oracle := fun input => oldOracle (Sum.inr input))
    (reply := V8SmzaMathPrivacy.response stage.gamma
      (currentHeads values base q) base.2.2 m)
    (transcript := Q38Rp05ChronologicalAlgebra.response
      (normalizedDsl components nonlinearRoot nodeDegree) statement
      stage.parameters (sourceWitnessPolynomials values base.1) q)
    (openedOracleEq := fun opening result =>
      recorded_physical_view_opened_oracle components nonlinearRoot nodeDegree
        certificates bound statement stage.parameters opening values base q m
        stage.gamma salt tapes labels result oldOracle accepted)

section RetainedProbabilityBridge

attribute [local irreducible] rp05CurrentPrefinal currentRequestResult
  recordedRequestProbability stagedPhysicalObservation uniformAverage
  HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames.run

private theorem recorded_run_input_frame
    {bound : Nat} {Work : Type} [Fintype Work]
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work))
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work)
    (sourceBytes stagedBytes : Except String (List Byte))
    (sourceOracle stagedOracle : Rp05FullRawInput bound → DigestRegister)
    (bytesEq : sourceBytes = stagedBytes)
    (oracleEq : sourceOracle = stagedOracle) :
    run true (next sourceBytes) sourceOracle state =
      run true (next stagedBytes) stagedOracle state := by
  exact congrArg₂
    (fun (bytes : Except String (List Byte))
        (currentOracle : Rp05FullRawInput bound → DigestRegister) =>
      run true (next bytes) currentOracle state)
    bytesEq oracleEq

private theorem retained_interpret_read_atomic
    {Other Result : Type} (oracle : Other → DigestRegister)
    (input : Other) (rest : DigestRegister → NonleafProgram Other Result) :
    NonleafProgram.interpret oracle (.read input rest) =
      NonleafProgram.interpret oracle (rest (oracle input)) := by
  rfl

private theorem retained_recorded_prefix_interpreted
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (labels : LeafIndex → DigestRegister)
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (computed : PrefinalResult × D)
    (hComputed : NonleafProgram.interpret oracle
      (rp05CurrentPrefinal bound largeEnough dsl statement salt labels values
        base masks widthBound) = computed) :
    NonleafProgram.interpret oracle
      (recordedPrefix largeEnough dsl statement values salt widthBound
        base masks labels) =
      let coefficients := Q38Rp05RequestCompiler.transcript dsl statement
        values base masks computed.1.piopGamma
      let digest := oracle (currentFinalKey bound (by omega)
        computed.1.hashFpp coefficients)
      NonleafProgram.interpret oracle
        (recordedPostFinal largeEnough dsl statement values base masks
          computed coefficients digest) := by
  simp only [recordedPrefix, NonleafProgram.interpret_bind]
  rw [hComputed]
  rw [retained_interpret_read_atomic]

private theorem retained_interpret_recordedPostFinal
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (computed : PrefinalResult × D) (coefficients : Q)
    (digest : DigestRegister)
    (oracle : Rp05OtherRawInput bound → DigestRegister) :
    NonleafProgram.interpret oracle
      (recordedPostFinal largeEnough dsl statement values base masks computed
        coefficients digest) =
      match certifyOpening (NonleafProgram.interpret oracle
          (rp05ChooseOpening bound (by omega) digest
            (sourcePendingFailure
              (sourcePendingFailure false computed.1.decsGamma)
              computed.1.piopGamma))) with
      | none => ⟨decodedParameters dsl statement computed.1.piopGamma,
          decodedQ38DecsGamma computed.1.decsGamma, computed.2, coefficients, digest,
          computed.1.tree, .nonceAbort⟩
      | some opening =>
          ⟨decodedParameters dsl statement computed.1.piopGamma,
            decodedQ38DecsGamma computed.1.decsGamma, computed.2, coefficients, digest,
            computed.1.tree, .opened opening
              (NonleafProgram.interpret oracle
                (currentSelectIndices bound largeEnough opening.points
                  (computed_opening_points_distinct opening) digest
                  (combinationHeads dsl statement
                    (decodedParameters dsl statement computed.1.piopGamma) opening.points
                    coefficients (sourceWitnessOpenings values opening.points base.1)
                    (sourcePcsFullView opening.points
                      (pcsBase opening.points masks.1 computed.2) base.2.1))
                  (earlier opening.points base.2.2) opening.pendingFailure))⟩ := by
  unfold recordedPostFinal
  dsimp only
  rw [NonleafProgram.interpret_bind]
  cases opened : certifyOpening (NonleafProgram.interpret oracle
      (rp05ChooseOpening bound (by omega) digest
        (sourcePendingFailure (sourcePendingFailure false computed.1.decsGamma)
          computed.1.piopGamma))) with
  | none => rfl
  | some opening =>
      rw [NonleafProgram.interpret_bind]
      rfl

private def retainedDynamicStageOfResult
    (dsl : RelationDsl) (statement : Statement)
    (result : PrefinalResult) : DynamicStage dsl statement :=
  ⟨decodedParameters dsl statement result.piopGamma,
    decodedQ38DecsGamma result.decsGamma, result.hashFpp,
    sourcePendingFailure (sourcePendingFailure false result.decsGamma)
      result.piopGamma,
    result.tree⟩

private theorem recorded_probability_eq_staged_of_computed
    {bound : Nat} {Work : Type} [Fintype Work]
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (labels : LeafIndex → DigestRegister)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work))
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work)
    (requestOracle : Rp05OtherRawInput bound → DigestRegister)
    (requestOracleEq : requestOracle =
      (fun input => oldOracle (Sum.inr input)))
    (decs : DecsStage) (result : PrefinalResult) (reply : D)
    (retainedStage : DynamicStage dsl statement)
    (retainedStageEq : retainedStage =
      retainedDynamicStageOfResult dsl statement result)
    (gammaEq : result.decsGamma = decs.decsGamma)
    (replyEq : reply = decsReply values base masks decs.decsGamma)
    (computedEq : NonleafProgram.interpret
      requestOracle
      (rp05CurrentPrefinal bound largeEnough dsl statement salt labels values
        base masks widthBound) = (result, reply)) :
    recordedRequestProbability true true largeEnough dsl statement values salt
        widthBound base masks labels next
        (fun input => oldOracle (Sum.inl input))
        requestOracle state =
      uniformAverage (fun tapes : TapeTable =>
        stagedPhysicalObservation largeEnough dsl statement values base masks.1
          masks.2 salt tapes labels retainedStage
          oldOracle state next) := by
  cases requestOracleEq
  let oracle := fun input => oldOracle (Sum.inr input)
  have oracleEta : Sum.elim (fun input => oldOracle (Sum.inl input)) oracle =
      oldOracle := by funext input; cases input <;> rfl
  have oracleOtherEq : oracle = (fun input => oldOracle (Sum.inr input)) := by
    funext input
    exact congrArg (fun currentOracle => currentOracle (Sum.inr input)) oracleEta
  have retainedStageParametersEq :
      retainedStage.parameters = decodedParameters dsl statement result.piopGamma := by
    simpa only [retainedDynamicStageOfResult] using
      congrArg (fun currentStage : DynamicStage dsl statement => currentStage.parameters)
        retainedStageEq
  have retainedStageGammaEq :
      retainedStage.gamma = decodedQ38DecsGamma result.decsGamma := by
    simpa only [retainedDynamicStageOfResult] using
      congrArg (fun currentStage : DynamicStage dsl statement => currentStage.gamma)
        retainedStageEq
  have retainedStageHashEq : retainedStage.hashFpp = result.hashFpp := by
    simpa only [retainedDynamicStageOfResult] using
      congrArg (fun currentStage : DynamicStage dsl statement => currentStage.hashFpp)
        retainedStageEq
  have retainedStagePendingEq :
      retainedStage.pending =
        sourcePendingFailure (sourcePendingFailure false result.decsGamma)
          result.piopGamma := by
    simpa only [retainedDynamicStageOfResult] using
      congrArg (fun currentStage : DynamicStage dsl statement => currentStage.pending)
        retainedStageEq
  have retainedStageTreeEq : retainedStage.tree = result.tree := by
    simpa only [retainedDynamicStageOfResult] using
      congrArg (fun currentStage : DynamicStage dsl statement => currentStage.tree)
        retainedStageEq
  unfold recordedRequestProbability
  apply congrArg uniformAverage
  funext tapes
  have emptyOverlayEq :
      overlay (fun input => oldOracle (Sum.inl input)) oracle labels statement salt
        (q38PhysicalSuffix (currentHeads values base masks.1) base.2.2 masks.2)
        (∅ : Finset LeafIndex) tapes =
      Sum.elim (fun input => oldOracle (Sum.inl input)) oracle := by
    funext input
    cases input <;> simp [overlay, support]
  rw [oracleEta, current_request_result_eq_recorded]
  rw [retained_recorded_prefix_interpreted largeEnough dsl statement values
    salt widthBound base masks labels oracle (result, reply) computedEq]
  rw [retained_interpret_recordedPostFinal largeEnough dsl statement values
    base masks (result, reply)
    (Q38Rp05RequestCompiler.transcript dsl statement values base masks
      result.piopGamma)
    (oracle (currentFinalKey bound (by omega) result.hashFpp
      (Q38Rp05RequestCompiler.transcript dsl statement values base masks
        result.piopGamma))) oracle]
  rw [show (result, reply).1 = result from rfl]
  rw [show (result, reply).2 = reply from rfl]
  have openingEq :
      certifyOpening (NonleafProgram.interpret oracle
        (rp05ChooseOpening bound (by omega)
          (oracle (currentFinalKey bound (by omega) result.hashFpp
            (Q38Rp05RequestCompiler.transcript dsl statement values base masks
              result.piopGamma)))
          (sourcePendingFailure (sourcePendingFailure false result.decsGamma)
            result.piopGamma))) =
      dynamicOpening largeEnough
        retainedStage oracle
        (Q38Rp05RequestCompiler.transcript dsl statement values base masks
          result.piopGamma) := by
    simp only [dynamicOpening, dynamicDigest,
      Q38Rp05RequestCompiler.transcript]
    rw [retainedStageHashEq, retainedStagePendingEq]
  rw [openingEq]
  let sourceTranscript := Q38Rp05RequestCompiler.transcript dsl statement
    values base masks result.piopGamma
  let stagedTranscript := Q38Rp05ChronologicalAlgebra.response dsl statement
    retainedStage.parameters (sourceWitnessPolynomials values base.1) masks.1
  have transcriptEq : sourceTranscript = stagedTranscript := by
    change Q38Rp05ChronologicalAlgebra.response dsl statement
        (decodedParameters dsl statement result.piopGamma)
        (sourceWitnessPolynomials values base.1) masks.1 = stagedTranscript
    exact congrArg
      (fun parameters => Q38Rp05ChronologicalAlgebra.response dsl statement
        parameters (sourceWitnessPolynomials values base.1) masks.1)
      retainedStageParametersEq.symm
  cases opened : dynamicOpening largeEnough
      retainedStage oracle sourceTranscript with
  | none =>
    have openedStage :
        dynamicOpening largeEnough retainedStage oracle stagedTranscript = none := by
      rw [← transcriptEq]
      exact opened
    let stagedReply := V8SmzaMathPrivacy.response retainedStage.gamma
      (currentHeads values base masks.1) base.2.2 masks.2
    let stagedDigest := dynamicDigest largeEnough retainedStage oracle stagedTranscript
    have stagedAbortEq :
        stagedPhysicalObservationCore largeEnough dsl statement values base
          masks.1 masks.2 salt tapes labels retainedStage oldOracle state next
          oracle stagedReply stagedTranscript stagedDigest
          (dynamicOpening largeEnough retainedStage oracle stagedTranscript) =
        run true (next (.error "smallwood opening nonce trial limit exhausted"))
          oldOracle state := by
      exact (congrArg
        (stagedPhysicalObservationCore largeEnough dsl statement values base
          masks.1 masks.2 salt tapes labels retainedStage oldOracle state next
          oracle stagedReply stagedTranscript stagedDigest)
        openedStage).trans rfl
    simp only [recordBytes, recordUnopened]
    rw [stagedPhysicalObservation, stagedAbortEq]
    have abortOverlayEq :
        overlay (fun input => oldOracle (Sum.inl input)) oracle labels statement salt
          (q38PhysicalSuffix (currentHeads values base masks.1) base.2.2 masks.2)
          (Finset.univᶜ) tapes = oldOracle := by
      calc
        overlay (fun input => oldOracle (Sum.inl input)) oracle labels statement salt
            (q38PhysicalSuffix (currentHeads values base masks.1) base.2.2 masks.2)
            (Finset.univᶜ) tapes =
          overlay (fun input => oldOracle (Sum.inl input)) oracle labels statement salt
            (q38PhysicalSuffix (currentHeads values base masks.1) base.2.2 masks.2)
            (∅ : Finset LeafIndex) tapes := by simp only [Finset.compl_univ]
        _ = Sum.elim (fun input => oldOracle (Sum.inl input)) oracle := emptyOverlayEq
        _ = oldOracle := oracleEta
    exact congrArg (fun currentOracle =>
      run true (next (.error "smallwood opening nonce trial limit exhausted"))
        currentOracle state) abortOverlayEq
  | some opening =>
    have openedStage :
        dynamicOpening largeEnough retainedStage oracle stagedTranscript =
          some opening := by
      rw [← transcriptEq]
      exact opened
    let stagedReply := V8SmzaMathPrivacy.response retainedStage.gamma
      (currentHeads values base masks.1) base.2.2 masks.2
    have stagedReplyEq : stagedReply = reply := by
      calc
        stagedReply = V8SmzaMathPrivacy.response
            (decodedQ38DecsGamma result.decsGamma)
            (currentHeads values base masks.1) base.2.2 masks.2 := by
          dsimp only [stagedReply]
          exact congrArg
            (fun gamma => V8SmzaMathPrivacy.response gamma
              (currentHeads values base masks.1) base.2.2 masks.2)
            retainedStageGammaEq
        _ = V8SmzaMathPrivacy.response
            (decodedQ38DecsGamma decs.decsGamma)
            (currentHeads values base masks.1) base.2.2 masks.2 := by
          exact congrArg
            (fun gamma => V8SmzaMathPrivacy.response gamma
              (currentHeads values base masks.1) base.2.2 masks.2)
            (congrArg decodedQ38DecsGamma gammaEq)
        _ = decsReply values base masks decs.decsGamma := rfl
        _ = reply := replyEq.symm
    let sourceDigest := oracle
      (currentFinalKey bound (by omega) result.hashFpp sourceTranscript)
    let stagedDigest := dynamicDigest largeEnough retainedStage
      (fun input => oldOracle (Sum.inr input)) stagedTranscript
    have digestEq : sourceDigest = stagedDigest := by
      change oracle (currentFinalKey bound (by omega) result.hashFpp sourceTranscript) =
        (fun input => oldOracle (Sum.inr input))
          (currentFinalKey bound (by omega) retainedStage.hashFpp stagedTranscript)
      rw [oracleOtherEq, retainedStageHashEq, ← transcriptEq]
    let sourceSelected := NonleafProgram.interpret oracle
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) sourceDigest
        (combinationHeads dsl statement
          (decodedParameters dsl statement result.piopGamma) opening.points
          sourceTranscript (sourceWitnessOpenings values opening.points base.1)
          (sourcePcsFullView opening.points (pcsBase opening.points masks.1 reply)
            base.2.1))
        (earlier opening.points base.2.2) opening.pendingFailure)
    let stagedSelected := NonleafProgram.interpret oracle
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) stagedDigest
        (combinationHeads dsl statement retainedStage.parameters opening.points
          stagedTranscript (sourceWitnessOpenings values opening.points base.1)
        (sourcePcsFullView opening.points
            (pcsBase opening.points masks.1 stagedReply) base.2.1))
        (earlier opening.points base.2.2) opening.pendingFailure)
    have selectedEq : sourceSelected = stagedSelected := by
      change NonleafProgram.interpret oracle
          (currentSelectIndices bound largeEnough opening.points
            (computed_opening_points_distinct opening) sourceDigest
            (combinationHeads dsl statement
              (decodedParameters dsl statement result.piopGamma) opening.points
              sourceTranscript (sourceWitnessOpenings values opening.points base.1)
              (sourcePcsFullView opening.points
                (pcsBase opening.points masks.1 reply) base.2.1))
            (earlier opening.points base.2.2) opening.pendingFailure) =
        NonleafProgram.interpret oracle
          (currentSelectIndices bound largeEnough opening.points
            (computed_opening_points_distinct opening) stagedDigest
            (combinationHeads dsl statement retainedStage.parameters opening.points
              stagedTranscript (sourceWitnessOpenings values opening.points base.1)
              (sourcePcsFullView opening.points
                (pcsBase opening.points masks.1 stagedReply) base.2.1))
            (earlier opening.points base.2.2) opening.pendingFailure)
      rw [retainedStageParametersEq, transcriptEq, digestEq, stagedReplyEq]
    let sourceBytes := selectedBytes dsl statement
      (decodedParameters dsl statement result.piopGamma) opening
      (decodedQ38DecsGamma result.decsGamma) reply sourceTranscript sourceDigest
      salt result.tree tapes
      (selectedPhysicalView values base masks.1 reply sourceSelected) sourceSelected
    let stagedBytes := selectedBytes dsl statement retainedStage.parameters opening
      retainedStage.gamma stagedReply stagedTranscript stagedDigest salt
      retainedStage.tree tapes
      (selectedPhysicalView values base masks.1 stagedReply stagedSelected)
      stagedSelected
    have bytesEq : sourceBytes = stagedBytes := by
      change selectedBytes dsl statement
          (decodedParameters dsl statement result.piopGamma) opening
          (decodedQ38DecsGamma result.decsGamma) reply sourceTranscript sourceDigest
          salt result.tree tapes
          (selectedPhysicalView values base masks.1 reply sourceSelected) sourceSelected =
        selectedBytes dsl statement retainedStage.parameters opening
          retainedStage.gamma stagedReply stagedTranscript stagedDigest salt
          retainedStage.tree tapes
          (selectedPhysicalView values base masks.1 stagedReply stagedSelected)
          stagedSelected
      rw [retainedStageParametersEq, retainedStageGammaEq, stagedReplyEq,
        ← transcriptEq, ← digestEq, retainedStageTreeEq, ← selectedEq]
    let sourceOracle := overlay (fun input => oldOracle (Sum.inl input)) oracle
      labels statement salt
      (q38PhysicalSuffix (currentHeads values base masks.1) base.2.2 masks.2)
      (if True then (rp05AbortAwareUnopened sourceSelected)ᶜ
        else Finset.univ) tapes
    let stagedOracle := overlay (fun input => oldOracle (Sum.inl input))
      (fun input => oldOracle (Sum.inr input))
      labels statement salt
      (q38PhysicalSuffix (currentHeads values base masks.1) base.2.2 masks.2)
      (rp05AbortAwareUnopened stagedSelected)ᶜ tapes
    have oracleEq : sourceOracle = stagedOracle := by
      change overlay (fun input => oldOracle (Sum.inl input)) oracle labels
          statement salt
          (q38PhysicalSuffix (currentHeads values base masks.1) base.2.2 masks.2)
          (if True then (rp05AbortAwareUnopened sourceSelected)ᶜ
            else Finset.univ) tapes =
        overlay (fun input => oldOracle (Sum.inl input))
          (fun input => oldOracle (Sum.inr input)) labels statement salt
          (q38PhysicalSuffix (currentHeads values base masks.1) base.2.2 masks.2)
          (rp05AbortAwareUnopened stagedSelected)ᶜ tapes
      simp only [ite_true]
      rw [oracleOtherEq, ← selectedEq]
    have stagedSomeEq :
        stagedPhysicalObservationCore largeEnough dsl statement values base
          masks.1 masks.2 salt tapes labels retainedStage oldOracle state next
          oracle stagedReply stagedTranscript stagedDigest
          (dynamicOpening largeEnough retainedStage oracle stagedTranscript) =
        run true (next stagedBytes) stagedOracle state := by
      exact (congrArg
        (stagedPhysicalObservationCore largeEnough dsl statement values base
          masks.1 masks.2 salt tapes labels retainedStage oldOracle state next
          oracle stagedReply stagedTranscript stagedDigest)
        openedStage).trans rfl
    simp only [recordBytes, recordUnopened]
    rw [stagedPhysicalObservation, stagedSomeEq]
    exact recorded_run_input_frame state next sourceBytes stagedBytes
      sourceOracle stagedOracle bytesEq oracleEq

private theorem retained_prefinal_result_computed_eq
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (salt : SaltBytes)
    (labels : LeafIndex → DigestRegister)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (oracle : Rp05OtherRawInput bound → DigestRegister) :
    let shape := rp05CurrentPrefinalShape bound largeEnough dsl statement
      salt labels widthBound
    let decs := NonleafProgram.interpret oracle (decsPrefix shape)
    let gamma := decodedQ38DecsGamma decs.decsGamma
    let reply := V8SmzaMathPrivacy.response gamma
      (currentHeads values base masks.1) base.2.2 masks.2
    let result := NonleafProgram.interpret oracle (piopSuffix shape decs reply)
    NonleafProgram.interpret oracle
        (rp05CurrentPrefinal bound largeEnough dsl statement salt labels
          values base masks widthBound) = (result, reply) := by
  exact current_prefinal_fixed_oracle_stage bound largeEnough dsl statement salt
    labels values base masks widthBound oracle

private theorem retained_dynamic_stage_eq
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (salt : SaltBytes)
    (labels : LeafIndex → DigestRegister)
    (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (oracle : Rp05OtherRawInput bound → DigestRegister) (reply : D) :
    let shape := rp05CurrentPrefinalShape bound largeEnough dsl statement
      salt labels widthBound
    let decs := NonleafProgram.interpret oracle (decsPrefix shape)
    let result := NonleafProgram.interpret oracle (piopSuffix shape decs reply)
    dynamicStage largeEnough dsl statement salt labels widthBound oracle reply =
      retainedDynamicStageOfResult dsl statement result := by
  rfl

private theorem retained_actual_reply_gamma_eq
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (labels : LeafIndex → DigestRegister)
    (oracle : Rp05OtherRawInput bound → DigestRegister) :
    let shape := rp05CurrentPrefinalShape bound largeEnough dsl statement salt
      labels widthBound
    let decs := NonleafProgram.interpret oracle (decsPrefix shape)
    let gamma := decodedQ38DecsGamma decs.decsGamma
    let reply := V8SmzaMathPrivacy.response gamma
      (currentHeads values base masks.1) base.2.2 masks.2
    let result := NonleafProgram.interpret oracle (piopSuffix shape decs reply)
    result.decsGamma = decs.decsGamma ∧
      reply = decsReply values base masks decs.decsGamma := by
  intro shape decs gamma reply result
  exact ⟨piop_suffix_decs_gamma shape oracle decs reply, rfl⟩

/-- The actual source request and the staged physical observation are the
same at each source-coin choice, before any change of variables. The tape
average remains the exact product law of the real retained-opening game. -/
theorem recorded_probability_eq_staged
    {bound : Nat} {Work : Type} [Fintype Work]
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (labels : LeafIndex → DigestRegister)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work))
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work) :
    let oracle := fun input => oldOracle (Sum.inr input)
    let shape := rp05CurrentPrefinalShape bound largeEnough dsl statement salt
      labels widthBound
    let gamma := decodedQ38DecsGamma
      (NonleafProgram.interpret oracle (decsPrefix shape)).decsGamma
    let reply := V8SmzaMathPrivacy.response gamma
      (currentHeads values base masks.1) base.2.2 masks.2
    recordedRequestProbability true true largeEnough dsl statement values salt
        widthBound base masks labels next (fun input => oldOracle (Sum.inl input))
        oracle state =
      uniformAverage (fun tapes : TapeTable =>
        stagedPhysicalObservation largeEnough dsl statement values base masks.1
          masks.2 salt tapes labels
          (dynamicStage largeEnough dsl statement salt labels widthBound oracle reply)
          oldOracle state next) := by
  intro oracle shape gamma reply
  let decs := NonleafProgram.interpret oracle (decsPrefix shape)
  let result := NonleafProgram.interpret oracle (piopSuffix shape decs reply)
  have ⟨gammaEq, replyEq⟩ := retained_actual_reply_gamma_eq largeEnough dsl
    statement values salt widthBound base masks labels oracle
  have computedEq : NonleafProgram.interpret oracle
      (rp05CurrentPrefinal bound largeEnough dsl statement salt labels values
        base masks widthBound) = (result, reply) :=
    retained_prefinal_result_computed_eq largeEnough dsl statement salt
      labels values base masks widthBound oracle
  have stageEq :
      dynamicStage largeEnough dsl statement salt labels widthBound oracle reply =
        retainedDynamicStageOfResult dsl statement result :=
    retained_dynamic_stage_eq largeEnough dsl statement salt labels widthBound
      oracle reply
  exact recorded_probability_eq_staged_of_computed
    largeEnough dsl statement values salt widthBound base masks labels oldOracle
    state next oracle rfl decs result reply
    (dynamicStage largeEnough dsl statement salt labels widthBound oracle reply)
    stageEq gammaEq replyEq computedEq

end RetainedProbabilityBridge

/-- This is the actual retained physical B,Q,M average after the literal
request has been staged. Its normalizer is the exact source coin cardinality;
there is no normalization of oracle or sampler branches. -/
def retainedSourceAverage
    {bound : Nat} {Work : Type} [Fintype Work]
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work))
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work) : ℝ :=
  let oracle := fun input => oldOracle (Sum.inr input)
  let shape := rp05CurrentPrefinalShape bound largeEnough dsl statement salt
    labels widthBound
  let gamma := decodedQ38DecsGamma
    (NonleafProgram.interpret oracle (decsPrefix shape)).decsGamma
  (∑ base : RemainingCoins Goldilocks, ∑ q : Q, ∑ m : D,
    let reply := V8SmzaMathPrivacy.response gamma
      (currentHeads values base q) base.2.2 m
    stagedPhysicalObservation largeEnough dsl statement values base q m salt
      tapes labels
      (dynamicStage largeEnough dsl statement salt labels widthBound oracle reply)
      oldOracle state next) /
    ((Fintype.card (RemainingCoins Goldilocks) : ℝ) *
      Fintype.card Q * Fintype.card D)

open HegemonCrypto.SmallWood.V8Smz9CurrentProgramOpeningBinding (physicalHeads)

/-- The demanded physical-to-algebra equality. The observer runs the actual
future program on the same old-H state and reconstructed retained oracle.
Accepted current-DSL constraints discharge the payload equation; that equation
is proved above and is NOT supplied as a caller premise. -/

theorem retained_source_average_eq_dependent_p10_source
    {bound : Nat} {Work : Type} [Fintype Work]
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates
      (normalizedDsl components nonlinearRoot nodeDegree))
    (largeEnough : 39162 ≤ bound) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes)
    (widthBound : 5 * (normalizedDsl components nonlinearRoot nodeDegree).width
      statement ≤ 2 ^ 24)
    (abortPoints : Fin 6 → Goldilocks)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work))
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work)
    (accepted : components.AcceptsPacked (currentPublicWords statement)
      (rp05PackValues values)) :
    let dsl := normalizedDsl components nonlinearRoot nodeDegree
    let oracle := fun input => oldOracle (Sum.inr input)
    let stages := dynamicStage largeEnough dsl statement salt labels widthBound oracle
    let shape := rp05CurrentPrefinalShape bound largeEnough dsl statement salt
      labels widthBound
    let gamma := decodedQ38DecsGamma
      (NonleafProgram.interpret oracle (decsPrefix shape)).decsGamma
    let parameters := fun reply (_ : Unit) => (stages reply).parameters
    let points := fun reply (_ : Unit) transcript =>
      dynamicPoints abortPoints
        (dynamicOpening largeEnough (stages reply) oracle transcript)
    let choose := fun reply (_ : Unit) transcript =>
      dynamicChoose largeEnough dsl statement abortPoints (stages reply) oracle transcript
    let kernel := fun reply (_ : Unit) transcript view =>
      dynamicKernel largeEnough dsl statement salt tapes (stages reply)
        oracle reply transcript view
        (dynamicContinuationObservation dsl statement salt tapes labels oldOracle
          state next)
    retainedSourceAverage largeEnough dsl statement values salt widthBound tapes
        labels oldOracle state next =
      sourceRequestAverage dsl statement gamma values parameters points choose kernel := by
  dsimp only
  unfold retainedSourceAverage sourceRequestAverage sourceRequestKernelSum
  apply congrArg (fun value : ℝ => value /
    ((Fintype.card (RemainingCoins Goldilocks) : ℝ) * Fintype.card Q * Fintype.card D))
  apply Finset.sum_congr rfl
  intro base _
  apply Finset.sum_congr rfl
  intro q _
  apply Finset.sum_congr rfl
  intro m _
  simp only [Fintype.sum_unique]
  let dsl := normalizedDsl components nonlinearRoot nodeDegree
  let oracle := fun input => oldOracle (Sum.inr input)
  let shape := rp05CurrentPrefinalShape bound largeEnough dsl statement salt
    labels widthBound
  let gamma := decodedQ38DecsGamma
    (NonleafProgram.interpret oracle (decsPrefix shape)).decsGamma
  let reply := V8SmzaMathPrivacy.response gamma
    (currentHeads values base q) base.2.2 m
  let stage := dynamicStage largeEnough dsl statement salt labels widthBound oracle reply
  let transcript := Q38Rp05ChronologicalAlgebra.response dsl statement
    stage.parameters (sourceWitnessPolynomials values base.1) q
  have stageGamma : stage.gamma = gamma :=
    dynamic_stage_gamma largeEnough dsl statement salt labels widthBound oracle reply
  have localEq := staged_physical_observation_eq_dynamic_kernel components
    nonlinearRoot nodeDegree certificates largeEnough statement values base q m
    abortPoints salt tapes labels
    stage
    oldOracle state next accepted
  have viewEq :
      dynamicSourceView largeEnough dsl statement values base q abortPoints
          stage oracle reply transcript =
        partialChronologicalView values
          (dynamicPoints abortPoints (dynamicOpening largeEnough stage oracle transcript))
          (fun _ => pcsBase
            (dynamicPoints abortPoints (dynamicOpening largeEnough stage oracle transcript))
            q reply)
          (fun witness pcs =>
            physicalHeads (sourceWitnessPolynomials values witness) q pcs)
          (dynamicChoose largeEnough dsl statement abortPoints stage oracle transcript)
          base := by
    simp only [dynamicSourceView, dynamicSourceViewCore, dynamicPoints,
      dynamicChoose, dynamicChooseCore, currentPhysicalHeadsView]
    rfl
  have kernelViewEq := congrArg
    (fun view => dynamicKernel largeEnough dsl statement salt tapes stage oracle
      reply transcript view
      (dynamicContinuationObservation dsl statement salt tapes labels oldOracle
        state next)) viewEq
  dsimp only at localEq
  rw [stageGamma] at localEq
  exact localEq.trans kernelViewEq

/-- Witness-free current simulator denotation. Parameters and outcomes are
computed in source chronology, and the exact observer retains the old H
fiber state plus the recorded 38-write overlay. -/
def dependentPublicAverage
    {bound : Nat} {Work : Type} [Fintype Work]
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (salt : SaltBytes)
    (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (abortPoints : Fin 6 → Goldilocks)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work))
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work) : ℝ :=
  let oracle := fun input => oldOracle (Sum.inr input)
  let stages := dynamicStage largeEnough dsl statement salt labels widthBound oracle
  let points := fun reply (_ : Unit) transcript =>
    dynamicPoints abortPoints
      (dynamicOpening largeEnough (stages reply) oracle transcript)
  let choose := fun reply (_ : Unit) transcript =>
    dynamicChoose largeEnough dsl statement abortPoints (stages reply) oracle transcript
  let kernel := fun reply (_ : Unit) transcript view =>
    dynamicKernel largeEnough dsl statement salt tapes (stages reply)
      oracle reply transcript view
      (dynamicContinuationObservation dsl statement salt tapes labels oldOracle
        state next)
  publicRequestAverage points choose kernel

/-- The retained physical source average equals the concrete witness-free
P10 average on the SAME arbitrary old-H state. No oracle-family alignment,
desired game equality, or security bound is a hypothesis. -/
theorem retained_source_average_eq_public
    {bound : Nat} {Work : Type} [Fintype Work]
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates
      (normalizedDsl components nonlinearRoot nodeDegree))
    (largeEnough : 39162 ≤ bound) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes)
    (widthBound : 5 * (normalizedDsl components nonlinearRoot nodeDegree).width
      statement ≤ 2 ^ 24)
    (abortPoints : Fin 6 → Goldilocks)
    (abortAdmissible : Smz9WitnessInterpolationAdmissible abortPoints)
    (abortNonzero : ∀ index, abortPoints index ≠ 0)
    (abortTargets : Targets abortPoints)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work))
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work)
    (accepted : components.AcceptsPacked (currentPublicWords statement)
      (rp05PackValues values)) :
    retainedSourceAverage largeEnough
        (normalizedDsl components nonlinearRoot nodeDegree) statement values salt
        widthBound tapes labels oldOracle state next =
      dependentPublicAverage largeEnough
        (normalizedDsl components nonlinearRoot nodeDegree) statement salt
        widthBound abortPoints tapes labels oldOracle state next := by
  exact (retained_source_average_eq_dependent_p10_source components nonlinearRoot
    nodeDegree certificates largeEnough statement values salt widthBound abortPoints
    tapes labels oldOracle state next accepted).trans
    (current_dependent_p10_normalized largeEnough
      (normalizedDsl components nonlinearRoot nodeDegree) statement salt labels
      widthBound values abortPoints abortAdmissible abortNonzero abortTargets tapes
      (fun input => oldOracle (Sum.inr input))
      (dynamicContinuationObservation
        (normalizedDsl components nonlinearRoot nodeDegree) statement salt tapes
        labels oldOracle state next))

theorem three_uniform_averages_eq_normalized_sum
    {A B C : Type} [Fintype A] [Nonempty A] [Fintype B] [Nonempty B]
    [Fintype C] [Nonempty C] (value : A → B → C → ℝ) :
    uniformAverage (fun a => uniformAverage (fun b => uniformAverage (value a b))) =
      (∑ a, ∑ b, ∑ c, value a b c) /
        ((Fintype.card A : ℝ) * Fintype.card B * Fintype.card C) := by
  unfold uniformAverage
  simp only [uniformFintypePMF_apply, ENNReal.toReal_inv, ENNReal.toReal_natCast,
    div_eq_mul_inv, mul_inv_rev, Finset.mul_sum, Finset.sum_mul]
  apply Finset.sum_congr rfl
  intro a _
  apply Finset.sum_congr rfl
  intro b _
  apply Finset.sum_congr rfl
  intro c _
  ring

/-- Exact original B,(Q,M),t source law, without conditioning on successful
sampling, equals the staged source average. The full source normalizer is
derived from the finite uniform PMF, not postulated. -/
theorem recorded_coin_average_eq_staged_average
    {bound : Nat} {Work : Type} [Fintype Work]
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (labels : LeafIndex → DigestRegister)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work))
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work) :
    uniformAverage (fun base : RemainingCoins Goldilocks =>
      uniformAverage (fun masks : Q × D =>
        recordedRequestProbability true true largeEnough dsl statement values salt
          widthBound base masks labels next (fun input => oldOracle (Sum.inl input))
          (fun input => oldOracle (Sum.inr input)) state)) =
      uniformAverage (fun tapes : TapeTable =>
        retainedSourceAverage largeEnough dsl statement values salt widthBound
          tapes labels oldOracle state next) := by
  simp_rw [recorded_probability_eq_staged]
  rw [← uniform_average_product]
  rw [uniform_average_comm]
  apply congrArg uniformAverage
  funext tapes
  let value : RemainingCoins Goldilocks → Q × D → ℝ :=
    fun base masks => stagedPhysicalObservation largeEnough dsl statement values
      base masks.1 masks.2 salt tapes labels
      (dynamicStage largeEnough dsl statement salt labels widthBound
        (fun input => oldOracle (Sum.inr input))
        (V8SmzaMathPrivacy.response
          (decodedQ38DecsGamma
            (NonleafProgram.interpret
              (fun input => oldOracle (Sum.inr input))
              (decsPrefix (rp05CurrentPrefinalShape bound largeEnough dsl statement
                salt labels widthBound))).decsGamma)
          (currentHeads values base masks.1) base.2.2 masks.2))
      oldOracle state next
  change uniformAverage
      (fun pair : RemainingCoins Goldilocks × (Q × D) => value pair.1 pair.2) =
    retainedSourceAverage largeEnough dsl statement values salt widthBound tapes
      labels oldOracle state next
  rw [uniform_average_product (A := RemainingCoins Goldilocks) (B := Q × D) value]
  have innerEq (base : RemainingCoins Goldilocks) :
      uniformAverage (fun masks : Q × D => value base masks) =
        uniformAverage (fun q : Q =>
          uniformAverage (fun m : D => value base (q, m))) := by
    exact uniform_average_product (A := Q) (B := D)
      (fun q m => value base (q, m))
  calc
    uniformAverage (fun base : RemainingCoins Goldilocks =>
        uniformAverage (fun masks : Q × D => value base masks)) =
      uniformAverage (fun base : RemainingCoins Goldilocks =>
        uniformAverage (fun q : Q =>
          uniformAverage (fun m : D => value base (q, m)))) :=
      congrArg uniformAverage (funext innerEq)
    _ = _ := three_uniform_averages_eq_normalized_sum
      (fun base q m => value base (q, m))

/-- The physical retained game with its exact original source-coin law is
the witness-free current public simulator on the unchanged H/state. This is
the actual retained-game P10 equality, not a premise for a later theorem. -/
theorem recorded_coin_average_eq_public
    {bound : Nat} {Work : Type} [Fintype Work]
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates
      (normalizedDsl components nonlinearRoot nodeDegree))
    (largeEnough : 39162 ≤ bound) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes)
    (widthBound : 5 * (normalizedDsl components nonlinearRoot nodeDegree).width
      statement ≤ 2 ^ 24)
    (abortPoints : Fin 6 → Goldilocks)
    (abortAdmissible : Smz9WitnessInterpolationAdmissible abortPoints)
    (abortNonzero : ∀ index, abortPoints index ≠ 0)
    (abortTargets : Targets abortPoints)
    (labels : LeafIndex → DigestRegister)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work))
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work)
    (accepted : components.AcceptsPacked (currentPublicWords statement)
      (rp05PackValues values)) :
    uniformAverage (fun base : RemainingCoins Goldilocks =>
      uniformAverage (fun masks : Q × D =>
        recordedRequestProbability true true largeEnough
          (normalizedDsl components nonlinearRoot nodeDegree) statement values salt
          widthBound base masks labels next (fun input => oldOracle (Sum.inl input))
          (fun input => oldOracle (Sum.inr input)) state)) =
      uniformAverage (fun tapes : TapeTable =>
        dependentPublicAverage largeEnough
          (normalizedDsl components nonlinearRoot nodeDegree) statement salt
          widthBound abortPoints tapes labels oldOracle state next) := by
  rw [recorded_coin_average_eq_staged_average]
  apply congrArg uniformAverage
  funext tapes
  exact retained_source_average_eq_public components nonlinearRoot nodeDegree
    certificates largeEnough statement values salt widthBound abortPoints
    abortAdmissible abortNonzero abortTargets tapes labels oldOracle state next accepted

theorem full_leaf_overlay_eq_batch
    (bound : Nat) (statement : Statement) (salt : SaltBytes)
    (data : LeafIndex → Fin 1176 → Byte)
    (labels : LeafIndex → DigestRegister) (tapes : TapeTable)
    (oldOracle : Rp05FullRawInput bound → DigestRegister) :
    overlay (fun input => oldOracle (Sum.inl input))
        (fun input => oldOracle (Sum.inr input)) labels statement salt data
        Finset.univ tapes =
      updateRp05Batch 8388608
        (fun i => Sum.inl (rp05SourceLeafInput statement salt (data i) i (tapes i)))
        labels oldOracle := by
  let keys : LeafIndex → Rp05FullRawInput bound :=
    fun i => Sum.inl (rp05SourceLeafInput statement salt (data i) i (tapes i))
  have distinct : Function.Injective keys :=
    rp05_current_keys_injective 8388608 id (fun _ _ same => same)
      statement salt data tapes
  have supports : support (Other := Rp05OtherRawInput bound) statement salt data
      Finset.univ tapes = Finset.univ.image keys := rfl
  funext input
  by_cases member : input ∈ Finset.univ.image keys
  · obtain ⟨i, _, equal⟩ := Finset.mem_image.mp member
    subst input
    rw [update_rp05_batch_at 8388608 keys labels oldOracle distinct i]
    simp [overlay, supports, member, keys, rp05_source_leaf_index_projection]
  · have outside : ∀ i, input ≠ keys i := by
      intro i same
      exact member (Finset.mem_image.mpr ⟨i, Finset.mem_univ i, same.symm⟩)
    rw [update_rp05_batch_outside 8388608 keys labels oldOracle input outside]
    cases input <;> simp [overlay, supports, member]

theorem current_request_result_leaf_overlay_invariant
    {bound : Nat} (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (data : LeafIndex → Fin 1176 → Byte) (programmed : Finset LeafIndex)
    (oldOracle : Rp05FullRawInput bound → DigestRegister) :
    currentRequestResult largeEnough dsl statement values salt widthBound
        base masks tapes labels
        (overlay (fun input => oldOracle (Sum.inl input))
          (fun input => oldOracle (Sum.inr input)) labels statement salt data
          programmed tapes) =
      currentRequestResult largeEnough dsl statement values salt widthBound
        base masks tapes labels oldOracle := by
  rw [current_request_result_eq_recorded, current_request_result_eq_recorded]
  rw [leaf_overlay_nonleaf_function]

def recordedSourceAverage
    {bound : Nat} {Work : Type} [Fintype Work]
    (retainOnly : Bool) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work))
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work) : ℝ :=
  uniformAverage fun base : RemainingCoins Goldilocks =>
    uniformAverage fun masks : Q × D =>
      uniformAverage fun labels : LeafIndex → DigestRegister =>
        recordedRequestProbability retainOnly true largeEnough dsl statement
          values salt widthBound base masks labels next
          (fun input => oldOracle (Sum.inl input))
          (fun input => oldOracle (Sum.inr input)) state

/-- The complete fresh-input request probability is exactly the full
recorded-source average. This bridges the P7 source game to P8/P9, preserving
the same old H and state, with no fresh oracle or trace sampled in between. -/
theorem complete_request_eq_recorded_source_average
    {bound : Nat} {Work : Type} [Fintype Work]
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work))
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work) :
    run true (currentCompleteHonestRequest largeEnough dsl statement values salt
        widthBound next) oldOracle state =
      recordedSourceAverage false largeEnough dsl statement values salt widthBound
        oldOracle state next := by
  rw [current_complete_honest_request_result_average]
  unfold recordedSourceAverage
  apply congrArg uniformAverage
  funext base
  apply congrArg uniformAverage
  funext masks
  rw [uniform_average_comm]
  apply congrArg uniformAverage
  funext labels
  unfold recordedRequestProbability
  apply congrArg uniformAverage
  funext tapes
  simp only [Bool.false_eq_true, if_false]
  rw [← full_leaf_overlay_eq_batch,
    current_request_result_leaf_overlay_invariant]
  have eta : Sum.elim (fun input => oldOracle (Sum.inl input))
      (fun input => oldOracle (Sum.inr input)) = oldOracle := by
    funext input; cases input <;> rfl
  simp only [eta]

def publicSimulatorProbability
    {bound : Nat} {Work : Type} [Fintype Work]
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (salt : SaltBytes)
    (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (abortPoints : Fin 6 → Goldilocks)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work))
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work) : ℝ :=
  uniformAverage fun labels : LeafIndex → DigestRegister =>
    uniformAverage fun tapes : TapeTable =>
      dependentPublicAverage largeEnough dsl statement salt widthBound abortPoints
        tapes labels oldOracle state next

theorem recorded_source_average_eq_public_simulator
    {bound : Nat} {Work : Type} [Fintype Work]
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates
      (normalizedDsl components nonlinearRoot nodeDegree))
    (largeEnough : 39162 ≤ bound) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes)
    (widthBound : 5 * (normalizedDsl components nonlinearRoot nodeDegree).width
      statement ≤ 2 ^ 24)
    (abortPoints : Fin 6 → Goldilocks)
    (abortAdmissible : Smz9WitnessInterpolationAdmissible abortPoints)
    (abortNonzero : ∀ index, abortPoints index ≠ 0)
    (abortTargets : Targets abortPoints)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work))
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work)
    (accepted : components.AcceptsPacked (currentPublicWords statement)
      (rp05PackValues values)) :
    recordedSourceAverage true largeEnough
        (normalizedDsl components nonlinearRoot nodeDegree) statement values salt
        widthBound oldOracle state next =
      publicSimulatorProbability largeEnough
        (normalizedDsl components nonlinearRoot nodeDegree) statement salt
        widthBound abortPoints oldOracle state next := by
  unfold recordedSourceAverage publicSimulatorProbability
  rw [← uniform_average_product, uniform_average_comm]
  apply congrArg uniformAverage
  funext labels
  let value : RemainingCoins Goldilocks → Q × D → ℝ :=
    fun base masks => recordedRequestProbability true true largeEnough
      (normalizedDsl components nonlinearRoot nodeDegree) statement values salt
      widthBound base masks labels next
      (fun input => oldOracle (Sum.inl input))
      (fun input => oldOracle (Sum.inr input)) state
  change uniformAverage
      (fun pair : RemainingCoins Goldilocks × (Q × D) => value pair.1 pair.2) =
    uniformAverage (fun tapes : TapeTable =>
      dependentPublicAverage largeEnough
        (normalizedDsl components nonlinearRoot nodeDegree) statement salt
        widthBound abortPoints tapes labels oldOracle state next)
  rw [uniform_average_product (A := RemainingCoins Goldilocks) (B := Q × D) value]
  exact recorded_coin_average_eq_public components nonlinearRoot nodeDegree
    certificates largeEnough statement values salt widthBound abortPoints
    abortAdmissible abortNonzero abortTargets labels oldOracle state next accepted

/-- Full P8/P9/P10 comparison for the actual CURRENT complete request and
a witness-free public simulator, on an arbitrary old-oracle fiber state.
The source inequality includes no caller-supplied game identification. -/
theorem complete_request_vs_public_simulator_bound_mass
    {bound : Nat} {Work : Type} [Fintype Work]
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates
      (normalizedDsl components nonlinearRoot nodeDegree))
    (largeEnough : 39162 ≤ bound) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes)
    (widthBound : 5 * (normalizedDsl components nonlinearRoot nodeDegree).width
      statement ≤ 2 ^ 24)
    (abortPoints : Fin 6 → Goldilocks)
    (abortAdmissible : Smz9WitnessInterpolationAdmissible abortPoints)
    (abortNonzero : ∀ index, abortPoints index ≠ 0)
    (abortTargets : Targets abortPoints)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (state : GameState (Input := Rp05FullRawInput bound) (Work := Work))
    (next : Except String (List Byte) → Program (Rp05FullRawInput bound) Work)
    (queries : Nat) (bounded : ∀ bytes, queryCount (next bytes) ≤ queries)
    (accepted : components.AcceptsPacked (currentPublicWords statement)
      (rp05PackValues values)) :
    |run true (currentCompleteHonestRequest largeEnough
        (normalizedDsl components nonlinearRoot nodeDegree) statement values salt
        widthBound next) oldOracle state -
      publicSimulatorProbability largeEnough
        (normalizedDsl components nonlinearRoot nodeDegree) statement salt
        widthBound abortPoints oldOracle state next| ≤
      (4 * (queries : ℝ) / (2 : ℝ)^256) * ‖state‖^2 := by
  rw [complete_request_eq_recorded_source_average,
    ← recorded_source_average_eq_public_simulator components nonlinearRoot nodeDegree
      certificates largeEnough statement values salt widthBound abortPoints
      abortAdmissible abortNonzero abortTargets oldOracle state next accepted]
  unfold recordedSourceAverage
  apply uniform_average_difference_le
  intro base
  apply uniform_average_difference_le
  intro masks
  apply uniform_average_difference_le
  intro labels
  exact current_complete_recorded_probability_bound_mass true largeEnough
    (normalizedDsl components nonlinearRoot nodeDegree) statement values salt
    widthBound base masks labels next queries bounded
    (fun input => oldOracle (Sum.inl input))
    (fun input => oldOracle (Sum.inr input)) state

end
end HegemonCrypto.SmallWood.Q38Rp05RetainedKernelJoin
