import HegemonCrypto.SmallWoodV8Smz9SourceTailCsrChunks
import Mathlib.Data.List.Chain

namespace HegemonCrypto.SmallWood.V8Smz9SourceTailCsrTable

open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem csr_chunks037_member (chunk : List CsrExecutableAttempt) (member : chunk ∈ csrChunks037) :
    chunk ∈ csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (member)))))))))))))))))))))))))))))))))))))

theorem actual_tail_csr_entry (family : TailCsrFamily) (index : Fin family.count) :
    exactCsrAttempts[family.start + index.val]? = some (expectedTailCsrAttempt family index.val) := by
  have chunkBound : (family.start + index.val) / 32 - 592 < csrChunks037.length := by
    have length : csrChunks037.length = 52 := by decide
    rw [length]
    have bound := index.isLt
    cases family <;> simp only [TailCsrFamily.start, TailCsrFamily.count] at * <;> omega
  have chunkMember : expectedTailCsrChunk family index.val ∈ csrChunks037 := by
    unfold expectedTailCsrChunk
    rw [List.getD_eq_getElem _ _ chunkBound]
    exact List.getElem_mem chunkBound
  have member : expectedTailCsrAttempt family index.val ∈ exactCsrAttempts := by
    rw [← csr_chunks_equal_materialized_attempts]
    exact List.mem_flatten.mpr ⟨_,csr_chunks037_member _ chunkMember,expected_tail_csr_chunk_member family index⟩
  obtain ⟨position, found⟩ := List.getElem?_of_mem member
  have canonical := checkCsr_sound _ _ _ hgv8rp03_csr_check_passes position _ found
  have same : family.start + index.val = position := canonical.1.1
  rw [same]
  exact found

def selectedTailCsrIndices : List Nat :=
  tailCsrFamilies.flatMap fun family => (List.range family.count).map fun index => family.start + index

theorem selected_tail_csr_exact_count : selectedTailCsrIndices.length = 496 := by decide

theorem selected_tail_csr_indices_distinct : selectedTailCsrIndices.Nodup := by
  have adjacent : selectedTailCsrIndices.IsChain (· < ·) := by decide
  have ordered : selectedTailCsrIndices.Pairwise (· < ·) := List.isChain_iff_pairwise.mp adjacent
  exact ordered.imp (fun less => Nat.ne_of_lt less)

theorem selected_tail_csr_avoids_completed :
    selectedTailCsrIndices.all (fun index => decide
      (15560 < index ∧ ¬(15665 ≤ index ∧ index ≤ 15671) ∧
       ¬(15918 ≤ index ∧ index ≤ 17837) ∧ ¬(18715 ≤ index ∧ index ≤ 18778))) = true := by decide


end HegemonCrypto.SmallWood.V8Smz9SourceTailCsrTable
