import HegemonCrypto.SmallWoodV8Smz9SourceReplicateTable

namespace HegemonCrypto.SmallWood.V8Smz9SourceReplicateCsr
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 200000

theorem replicate_chunk_0 : replicateChunk 0 512 := by decide
theorem replicate_chunk_1 : replicateChunk 512 512 := by decide
theorem replicate_chunk_2 : replicateChunk 1024 512 := by decide
theorem replicate_chunk_3 : replicateChunk 1536 512 := by decide
theorem replicate_chunk_4 : replicateChunk 2048 512 := by decide
theorem replicate_chunk_5 : replicateChunk 2560 512 := by decide
theorem replicate_chunk_6 : replicateChunk 3072 512 := by decide
theorem replicate_chunk_7 : replicateChunk 3584 512 := by decide

end HegemonCrypto.SmallWood.V8Smz9SourceReplicateCsr
