import HegemonCrypto.SmallWoodV8Smz9SourceStableChunk64
import HegemonCrypto.SmallWoodV8Smz9SourceStableIssuerFrames
import HegemonCrypto.SmallWoodV8Smz9SourceStableLeafFrames
import HegemonCrypto.SmallWoodV8Smz9TypedScheduleInventory

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableDigestForward
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceStableNode48
open HegemonCrypto.SmallWood.V8Smz9SourceStableChunk64
open HegemonCrypto.SmallWood.V8Smz9SourceStableIssuerFrames
open HegemonCrypto.SmallWood.V8Smz9SourceStableLeafFrames
open HegemonCrypto.SmallWood.V8Smz9StableConfigHash
open HegemonCrypto.SmallWood.V8Smz9StableHashWiring
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
attribute [local irreducible] Poseidon2Width16Kernel.permutation poseidon2V8Compress14

theorem scheduled_compress_digest (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (call : Fin 125)
    (domain : Nat) (left right : List Nat)
    (frame : actualSourceFrame statement witness call = compressFrameWords domain left right) :
    finalDigest (scheduledFinal statement witness) call.val = poseidon2V8Compress14 domain left right := by
  rw [finalDigest,every_call_has_actual_kernel_final]
  have initial := typed_valid_initial_is_actual_source_frame statement witness valid call
  change stateWords (scheduledInitial statement witness call.val) = actualSourceFrame statement witness call at initial
  rw [initial,frame]
  exact compress_digest_is_exact_source domain left right

def sourceConfigChunkDigest (witness : V8Witness) (chunk : Nat) : List Nat :=
  poseidon2V8Compress14 (stablecoinV8ConfigChunkDomains.getD chunk 0)
    (fixedWords 7 ((stableConfigWords witness).drop (chunk*14)))
    (fixedWords 7 ((stableConfigWords witness).drop (chunk*14+7)))

theorem scheduled_config_chunk_digest (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (chunk : Fin 4) :
    finalDigest (scheduledFinal statement witness) (106+chunk.val) = sourceConfigChunkDigest witness chunk.val :=
  scheduled_compress_digest statement witness valid ⟨106+chunk.val,by omega⟩ _ _ _
    (actual_stable_chunk_frame statement witness chunk)

theorem scheduled_config_node_digest (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (node : Fin 3) :
    finalDigest (scheduledFinal statement witness) (110+node.val) =
      poseidon2V8Compress14 (nodeDomain node.val)
        (finalDigest (scheduledFinal statement witness) (nodeChild node.val 0))
        (finalDigest (scheduledFinal statement witness) (nodeChild node.val 1)) :=
  scheduled_compress_digest statement witness valid ⟨110+node.val,by omega⟩ _ _ _
    (actual_stable_node_frame statement witness node)

theorem config_words_encoded (witness : V8Witness) :
    stableConfigWords witness = encodeV8StablecoinConfig (decodeV8StablecoinConfig witness.stablecoin) := by
  rw [encode_decode_config]
  rfl

theorem config_chunk_left (fields : List Nat) (chunk : Nat) :
    ((List.range 14).map (fun lane => fields.getD (chunk*14+lane) 0)).take 7 =
      fixedWords 7 (fields.drop (chunk*14)) := by
  simp [List.range_succ,fixedWords,List.getD_eq_getElem?_getD,List.getElem?_drop]

theorem config_chunk_right (fields : List Nat) (chunk : Nat) :
    (((List.range 14).map (fun lane => fields.getD (chunk*14+lane) 0)).drop 7).take 7 =
      fixedWords 7 (fields.drop (chunk*14+7)) := by
  simp [List.range_succ,fixedWords,List.getD_eq_getElem?_getD,List.getElem?_drop,Nat.add_assoc]

theorem exact_config_digest_source_shape (witness : V8Witness) :
    exactV8StablecoinConfigDigest (decodeV8StablecoinConfig witness.stablecoin) =
      poseidon2V8Compress14 stablecoinV8DomainConfigRoot
        (poseidon2V8Compress14 stablecoinV8DomainConfigNode0 (sourceConfigChunkDigest witness 0) (sourceConfigChunkDigest witness 1))
        (poseidon2V8Compress14 stablecoinV8DomainConfigNode1 (sourceConfigChunkDigest witness 2) (sourceConfigChunkDigest witness 3)) := by
  unfold exactV8StablecoinConfigDigest
  rw [← config_words_encoded]
  let piece (chunk : Nat) := poseidon2V8Compress14 (stablecoinV8ConfigChunkDomains.getD chunk 0)
    (((List.range 14).map (fun lane => (stableConfigWords witness).getD (chunk*14+lane) 0)).take 7)
    ((((List.range 14).map (fun lane => (stableConfigWords witness).getD (chunk*14+lane) 0)).drop 7).take 7)
  change poseidon2V8Compress14 stablecoinV8DomainConfigRoot
    (poseidon2V8Compress14 stablecoinV8DomainConfigNode0 (piece 0) (piece 1))
    (poseidon2V8Compress14 stablecoinV8DomainConfigNode1 (piece 2) (piece 3)) = _
  have piece_eq (chunk : Nat) : piece chunk = sourceConfigChunkDigest witness chunk := by
    dsimp only [piece,sourceConfigChunkDigest]
    rw [config_chunk_left,config_chunk_right]
  rw [piece_eq,piece_eq,piece_eq,piece_eq]

theorem scheduled_config_digest (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    finalDigest (scheduledFinal statement witness) 112 =
      exactV8StablecoinConfigDigest (decodeV8StablecoinConfig witness.stablecoin) := by
  have n0 := scheduled_config_node_digest statement witness valid ⟨0,by decide⟩
  have n1 := scheduled_config_node_digest statement witness valid ⟨1,by decide⟩
  have n2 := scheduled_config_node_digest statement witness valid ⟨2,by decide⟩
  change finalDigest (scheduledFinal statement witness) 110 =
    poseidon2V8Compress14 stablecoinV8DomainConfigNode0
      (finalDigest (scheduledFinal statement witness) 106) (finalDigest (scheduledFinal statement witness) 107) at n0
  change finalDigest (scheduledFinal statement witness) 111 =
    poseidon2V8Compress14 stablecoinV8DomainConfigNode1
      (finalDigest (scheduledFinal statement witness) 108) (finalDigest (scheduledFinal statement witness) 109) at n1
  change finalDigest (scheduledFinal statement witness) 112 =
    poseidon2V8Compress14 stablecoinV8DomainConfigRoot
      (finalDigest (scheduledFinal statement witness) 110) (finalDigest (scheduledFinal statement witness) 111) at n2
  have c0 := scheduled_config_chunk_digest statement witness valid ⟨0,by decide⟩
  have c1 := scheduled_config_chunk_digest statement witness valid ⟨1,by decide⟩
  have c2 := scheduled_config_chunk_digest statement witness valid ⟨2,by decide⟩
  have c3 := scheduled_config_chunk_digest statement witness valid ⟨3,by decide⟩
  change finalDigest (scheduledFinal statement witness) 106 = _ at c0
  change finalDigest (scheduledFinal statement witness) 107 = _ at c1
  change finalDigest (scheduledFinal statement witness) 108 = _ at c2
  change finalDigest (scheduledFinal statement witness) 109 = _ at c3
  rw [exact_config_digest_source_shape,n2,n0,n1,c0,c1,c2,c3]

end HegemonCrypto.SmallWood.V8Smz9SourceStableDigestForward
