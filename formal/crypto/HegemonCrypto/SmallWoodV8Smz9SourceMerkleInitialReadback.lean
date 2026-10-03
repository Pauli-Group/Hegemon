import HegemonCrypto.SmallWoodV8Smz9SourceMerkleInitialFrames

namespace HegemonCrypto.SmallWood.V8Smz9SourceMerkleInitial
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies
open HegemonCrypto.SmallWood.V8Smz9SourceInlineRows
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000

theorem exact_initial_attempt_lookup (offset : Fin 1024) :
    exactCsrAttempts[15918+offset.val]? = some (V8Smz9InputMerkleSources.initialAttempt offset.val) :=
  exact_attempt_lookup _ (V8Smz9InputMerkleSources.exact_initial_attempt offset.isLt)

/-- Equality is supplied by the actual typed constructor, with arbitrary tail. -/
theorem typed_merkle_initial_rate (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (tail : List Nat)
    (step : Fin 64) (lane : Fin 14) :
    (typedAssignment statement witness tail).getD
        (hashInitialIndex (V8Smz9InputMerkleSources.merkleCall step.val) lane.val) 0 =
      (typedAssignment statement witness tail).getD
        (V8Smz9InputMerkleSources.inlineIndex step.val (lane.val%7) (if lane.val<7 then 1 else 2)) 0 := by
  rw [typed_initial_readback statement witness valid tail
    ⟨V8Smz9InputMerkleSources.merkleCall step.val, merkle_call_live step⟩ ⟨lane.val, by omega⟩,
    actual_merkle_frame_rate statement witness valid step lane, source_inline_index_agrees]
  symm
  exact constructed_orientation_readback statement witness _ tail
    ⟨step.val/32, by omega⟩ ⟨step.val%32, by omega⟩ ⟨lane.val%7, by omega⟩
    ⟨if lane.val<7 then 1 else 2, by split <;> decide⟩

theorem typed_merkle_initial_capacity (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (tail : List Nat)
    (step : Fin 64) (lane : Fin 16) (capacity : 14 ≤ lane.val) :
    (typedAssignment statement witness tail).getD
        (hashInitialIndex (V8Smz9InputMerkleSources.merkleCall step.val) lane.val) 0 =
      if lane.val=14 then 4 else poseidon2V8SuiteMarker := by
  rw [typed_initial_readback statement witness valid tail
    ⟨V8Smz9InputMerkleSources.merkleCall step.val, merkle_call_live step⟩ lane,
    actual_merkle_frame_capacity statement witness step lane capacity]

end HegemonCrypto.SmallWood.V8Smz9SourceMerkleInitial
