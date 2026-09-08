import HegemonCrypto.SmallWoodV8Smz9SourceReplicateChunksC

namespace HegemonCrypto.SmallWood.V8Smz9SourceReplicateCsr
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 200000

theorem replicate_chunk_24 : replicateChunk 12288 512 := by decide
theorem replicate_chunk_25 : replicateChunk 12800 512 := by decide
theorem replicate_chunk_26 : replicateChunk 13312 512 := by decide
theorem replicate_chunk_27 : replicateChunk 13824 512 := by decide
theorem replicate_chunk_28 : replicateChunk 14336 512 := by decide
theorem replicate_chunk_29 : replicateChunk 14848 512 := by decide
theorem replicate_chunk_30 : replicateChunk 15360 201 := by decide

end HegemonCrypto.SmallWood.V8Smz9SourceReplicateCsr
