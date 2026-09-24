import HegemonCrypto.SmallWoodV8Smz9SourceTypedPrefix

namespace HegemonCrypto.SmallWood.V8Smz9SourceReplicateCsr
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceReplicatedRows
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
set_option Elab.async false
set_option maxHeartbeats 800000
set_option maxRecDepth 10000

theorem constructed_first92_word (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (tail : List Nat) (row : Fin 92) (lane : Fin 64) :
    (constructedAssignment statement witness live tail).getD (row.val*64+lane.val) 0 =
      sourceWord statement witness row.val := by
  rw [constructed_first92_unchanged statement witness live tail ⟨row.val*64+lane.val, by omega⟩]
  have source := placed_source_word statement witness [] row.val lane.val row.isLt lane.isLt
  simpa only [placePrefix, List.append_nil, Poseidon2V8DecoderRefinement.rawIndex,
    Poseidon2V8DecoderRefinement.rawRowStart, Poseidon2V8DecoderRefinement.packingFactor,
    Nat.zero_add] using source

theorem constructed_auth_row_word (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (tail : List Nat) (row : Fin 155) (lane : Fin 64) :
    (constructedAssignment statement witness live tail).getD ((92+row.val)*64+lane.val) 0 =
      sourceAuthRow statement witness (computedAuthFinals live) row.val := by
  rw [constructed_as_auth_placement]
  have source := source_auth_embedded_getD (packedPrefix statement witness)
    (HegemonCrypto.SmallWood.V8Smz9SourceDenseMaterialization.sourceDensePacked
        (HegemonCrypto.SmallWood.V8Smz9SourceDenseMaterialization.typedSourceValues statement witness) ++
      HegemonCrypto.SmallWood.V8Smz9SourceInlineRows.inlinePacked live witness ++
        (hashRows live).flatten ++ tail)
    statement witness (computedAuthFinals live) row lane 0
  rw [packed_prefix_length] at source
  have address : 5888+row.val*64+lane.val = (92+row.val)*64+lane.val := by omega
  rwa [address] at source

/-- One actual value for every raw row, independent of the lane. Neither
semantic validity nor canonical tail data is needed for replication. -/
def constructedRawWord (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (row : Nat) : Nat :=
  if row < 92 then sourceWord statement witness row
  else sourceAuthRow statement witness (computedAuthFinals live) (row-92)

theorem constructed_all_raw_rows_readback (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (tail : List Nat) (row : Fin 247) (lane : Fin 64) :
    (constructedAssignment statement witness live tail).getD (row.val*64+lane.val) 0 =
      constructedRawWord statement witness live row.val := by
  by_cases first : row.val < 92
  · rw [constructedRawWord, if_pos first]
    exact constructed_first92_word statement witness live tail ⟨row.val, first⟩ lane
  · rw [constructedRawWord, if_neg first]
    have source := constructed_auth_row_word statement witness live tail ⟨row.val-92, by omega⟩ lane
    have address : 92+(row.val-92) = row.val := by omega
    simpa only [address] using source

theorem constructed_raw_lanes_equal (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (tail : List Nat) (row : Fin 247) (left right : Fin 64) :
    (constructedAssignment statement witness live tail).getD (row.val*64+left.val) 0 =
      (constructedAssignment statement witness live tail).getD (row.val*64+right.val) 0 := by
  rw [constructed_all_raw_rows_readback, constructed_all_raw_rows_readback]

theorem typed_raw_lanes_equal (statement : V8PublicStatement) (witness : V8Witness)
    (tail : List Nat) (row : Fin 247) (left right : Fin 64) :
    (typedAssignment statement witness tail).getD (row.val*64+left.val) 0 =
      (typedAssignment statement witness tail).getD (row.val*64+right.val) 0 :=
  constructed_raw_lanes_equal statement witness _ tail row left right

end HegemonCrypto.SmallWood.V8Smz9SourceReplicateCsr
