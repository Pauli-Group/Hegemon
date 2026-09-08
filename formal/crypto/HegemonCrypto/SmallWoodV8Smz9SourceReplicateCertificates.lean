import HegemonCrypto.SmallWoodV8Smz9SourceReplicateChunksD
import Mathlib.Data.Fintype.Fin
import Mathlib.Tactic.FinCases

namespace HegemonCrypto.SmallWood.V8Smz9SourceReplicateCsr
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
set_option Elab.async false
set_option maxHeartbeats 1200000
set_option maxRecDepth 10000

theorem exact_replicate_chunks (chunk : Fin 31) :
    replicateChunk (512*chunk.val) (min 512 (15561-512*chunk.val)) := by
  fin_cases chunk
  · exact replicate_chunk_0
  · exact replicate_chunk_1
  · exact replicate_chunk_2
  · exact replicate_chunk_3
  · exact replicate_chunk_4
  · exact replicate_chunk_5
  · exact replicate_chunk_6
  · exact replicate_chunk_7
  · exact replicate_chunk_8
  · exact replicate_chunk_9
  · exact replicate_chunk_10
  · exact replicate_chunk_11
  · exact replicate_chunk_12
  · exact replicate_chunk_13
  · exact replicate_chunk_14
  · exact replicate_chunk_15
  · exact replicate_chunk_16
  · exact replicate_chunk_17
  · exact replicate_chunk_18
  · exact replicate_chunk_19
  · exact replicate_chunk_20
  · exact replicate_chunk_21
  · exact replicate_chunk_22
  · exact replicate_chunk_23
  · exact replicate_chunk_24
  · exact replicate_chunk_25
  · exact replicate_chunk_26
  · exact replicate_chunk_27
  · exact replicate_chunk_28
  · exact replicate_chunk_29
  · exact replicate_chunk_30

theorem replicate_chunk_entry (start count : Nat) (checked : replicateChunk start count)
    (offset : Nat) (bound : offset < count) :
    exactCsrAttempts[start+offset]? = some (expectedReplicateAttempt (start+offset)) := by
  have atIndex := congrArg (fun rows : List CsrExecutableAttempt => rows[offset]?) checked
  simpa only [replicateChunk, List.getElem?_take, if_pos bound, List.getElem?_drop,
    List.getElem?_map, List.getElem?_range, bound, if_true, Option.map_some] using atIndex

/-- Every index is assigned to one of the 31 disjoint checked slices; the last
slice has 201 entries. There are exactly 15,561 distinct actual attempts. -/
theorem exact_replicate_attempt (index : Nat) (bound : index < 15561) :
    exactCsrAttempts[index]? = some (expectedReplicateAttempt index) := by
  have chunkBound : index/512 < 31 := by omega
  have localBound : index%512 < min 512 (15561-512*(index/512)) := by omega
  have address : 512*(index/512)+index%512 = index := by omega
  have found := replicate_chunk_entry (512*(index/512)) (min 512 (15561-512*(index/512)))
    (exact_replicate_chunks ⟨index/512, chunkBound⟩) (index%512) localBound
  simpa only [address] using found

theorem expected_replicate_row_lane (row lane : Nat) (positive : 1 ≤ lane) (laneBound : lane < 64) :
    expectedReplicateAttempt (row*63+lane-1) =
      attempt (row*63+lane-1) 0 (row*63+lane-1) 0 [(row*64+lane, 1), (row*64, 3)] 0 := by
  have quotient : (row*63+lane-1)/63 = row := by omega
  have remainder : (row*63+lane-1)%63+1 = lane := by omega
  simp only [expectedReplicateAttempt, quotient, remainder]

theorem exact_replicate_row_lane (row : Fin 247) (lane : Nat) (positive : 1 ≤ lane) (laneBound : lane < 64) :
    exactCsrAttempts[row.val*63+lane-1]? =
      some (attempt (row.val*63+lane-1) 0 (row.val*63+lane-1) 0
        [(row.val*64+lane, 1), (row.val*64, 3)] 0) := by
  rw [exact_replicate_attempt _ (by omega), expected_replicate_row_lane _ _ positive laneBound]

end HegemonCrypto.SmallWood.V8Smz9SourceReplicateCsr
