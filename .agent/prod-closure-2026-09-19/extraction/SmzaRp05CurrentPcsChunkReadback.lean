import SmzaRp05PcsWireProjection

/-! The actual two 368-word chunks of a 736-word source row have no padding
and read precisely the corresponding source column. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPcsChunkReadback

open SmzaRp05PcsWireProjection (chunkHeads paddedChunk)

set_option autoImplicit false

theorem actual_chunk_reads_source_column
    (values : Fin 736 → Goldilocks) (block : Fin 2) (column : Fin 368) :
    ((chunkHeads 2 368 (List.ofFn values)).getD block.val []).getD column.val 0 =
      values ⟨block.val * 368 + column.val, by
        have := block.isLt
        have := column.isLt
        omega⟩ := by
  have blockBound := block.isLt
  have columnBound := column.isLt
  have chunkLength :
      ((List.ofFn values).drop (block.val * 368) |>.take 368).length = 368 := by
    simp only [List.length_take, List.length_drop, List.length_ofFn]
    omega
  rw [List.getD_eq_getElem (chunkHeads 2 368 (List.ofFn values)) [] (by
    simpa only [chunkHeads, List.length_map, List.length_range] using blockBound)]
  simp only [chunkHeads, List.getElem_map, List.getElem_range, paddedChunk]
  rw [chunkLength, Nat.sub_self, List.replicate_zero, List.append_nil]
  rw [List.getD_eq_getElem _ _ (by simpa only [chunkLength] using columnBound)]
  simp only [List.getElem_take, List.getElem_drop, List.getElem_ofFn]

end HegemonCrypto.SmallWood.SmzaRp05CurrentPcsChunkReadback
