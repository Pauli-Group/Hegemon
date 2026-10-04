import HegemonCrypto.SmallWoodV8Smz9SourceLiveCsrChunks
import HegemonCrypto.SmallWoodV8Smz9SourceTailCsrTable

namespace HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrTable

open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem actual_live_csr_entry (family : LiveCsrFamily) (index : Fin family.count) :
    exactCsrAttempts[family.start + index.val]? = some (expectedLiveCsrAttempt family index.val) := by
  have chunkBound : (family.start + index.val) / 32 - 592 < csrChunks037.length := by
    have length : csrChunks037.length = 52 := by decide
    rw [length]
    have bound := index.isLt
    cases family <;> simp only [LiveCsrFamily.start, LiveCsrFamily.count] at * <;> omega
  have chunkMember : expectedLiveCsrChunk family index.val ∈ csrChunks037 := by
    unfold expectedLiveCsrChunk
    rw [List.getD_eq_getElem _ _ chunkBound]
    exact List.getElem_mem chunkBound
  have member : expectedLiveCsrAttempt family index.val ∈ exactCsrAttempts := by
    rw [← csr_chunks_equal_materialized_attempts]
    exact List.mem_flatten.mpr ⟨_,
      V8Smz9SourceTailCsrTable.csr_chunks037_member _ chunkMember,
      expected_live_csr_chunk_member family index⟩
  obtain ⟨position, found⟩ := List.getElem?_of_mem member
  have canonical := checkCsr_sound _ _ _ hgv8rp03_csr_check_passes position _ found
  have same : family.start + index.val = position := canonical.1.1
  rw [same]
  exact found

def selectedLiveCsrIndices : List Nat :=
  liveCsrFamilies.flatMap fun family => (List.range family.count).map fun index => family.start + index

theorem selected_live_csr_exact_count : selectedLiveCsrIndices.length = 345 := by decide

theorem selected_live_csr_indices_distinct : selectedLiveCsrIndices.Nodup := by
  have adjacent : selectedLiveCsrIndices.IsChain (· < ·) := by decide
  exact (List.isChain_iff_pairwise.mp adjacent).imp (fun less => Nat.ne_of_lt less)

theorem selected_live_csr_avoids_completed496 :
    selectedLiveCsrIndices.all (fun index => decide
      (¬(19262 ≤ index ∧ index ≤ 19279) ∧ ¬(19298 ≤ index ∧ index ≤ 19305) ∧
       ¬(19325 ≤ index ∧ index ≤ 19328) ∧ ¬(19333 ≤ index ∧ index ≤ 19343) ∧
       ¬(19554 ≤ index ∧ index ≤ 19859) ∧ ¬(20258 ≤ index ∧ index ≤ 20295) ∧
       ¬(20494 ≤ index ∧ index ≤ 20604))) = true := by decide


end HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrTable
