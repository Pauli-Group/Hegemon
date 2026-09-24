import HegemonCrypto.SmallWoodV8Smz9SourceNonmint40
import HegemonCrypto.SmallWoodV8Smz9SourceStablePadding24

namespace HegemonCrypto.SmallWood.V8Smz9SourceNonmintCsr40
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt)
open HegemonCrypto.SmallWood.V8Smz9SourceNonmint40
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies (exact_attempt_lookup)
open HegemonCrypto.SmallWood.V8Smz9SourceTailCsrTable (csr_chunks037_member)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

def nonmintAddress (index : Nat) : Nat :=
  if index < 8 then 42177 + index
  else if index < 36 then 42186 + index else 42098 + index

def nonmintAttempt (index : Nat) : CsrExecutableAttempt :=
  attempt (20335 + index) (if index < 8 then 69 else if index < 36 then 70 else 71)
    (if index < 8 then index else if index < 36 then index - 8 else index - 36)
    1 [(nonmintAddress index,308)] 0

theorem nonmint_attempt_chunk_member (index : Fin 40) :
    nonmintAttempt index.val ∈ V8Smz9ProgramCanonicalityCsr39.chunk011 ++
      V8Smz9ProgramCanonicalityCsr39.chunk012 := by
  fin_cases index <;> decide

theorem nonmint_chunks_in_complete (chunk : List CsrExecutableAttempt)
    (selected : chunk = V8Smz9ProgramCanonicalityCsr39.chunk011 ∨
      chunk = V8Smz9ProgramCanonicalityCsr39.chunk012) : chunk ∈ csrChunks000 := by
  have member : chunk ∈ V8Smz9ProgramCanonicalityCsr39.chunkList := by
    rcases selected with rfl | rfl
    all_goals simp only [V8Smz9ProgramCanonicalityCsr39.chunkList,List.mem_cons,List.not_mem_nil,or_false]
    · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl True.intro)))))))))))
    · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl True.intro))))))))))))
  exact csr_chunks037_member _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ member)))

theorem nonmint_exact_lookup (index : Fin 40) :
    exactCsrAttempts[20335 + index.val]? = some (nonmintAttempt index.val) := by
  apply exact_attempt_lookup (nonmintAttempt index.val)
  rw [←csr_chunks_equal_materialized_attempts]
  have member := List.mem_append.mp (nonmint_attempt_chunk_member index)
  rcases member with first | second
  · exact List.mem_flatten.mpr ⟨_,nonmint_chunks_in_complete _ (Or.inl rfl),first⟩
  · exact List.mem_flatten.mpr ⟨_,nonmint_chunks_in_complete _ (Or.inr rfl),second⟩

theorem full_candidate_nonmint_address_zero (statement : V8PublicStatement) (witness : V8Witness)
    (nonmint : statement.stablecoin.direction ≠ .mint) (index : Fin 40) :
    (fullTypedSourceCandidate statement witness).getD (nonmintAddress index.val) 0 = 0 := by
  by_cases low : index.val < 8
  · have zero := full_candidate_nonmint_numeric_zero statement witness nonmint (index.val + 1)
      (Or.inl ⟨by omega,by omega⟩)
    have address : 42176 + (index.val + 1) = nonmintAddress index.val := by
      rw [nonmintAddress,if_pos low]; omega
    rwa [address] at zero
  · by_cases middle : index.val < 36
    · have zero := full_candidate_nonmint_numeric_zero statement witness nonmint (index.val + 10)
        (Or.inr ⟨by omega,by omega⟩)
      have address : 42176 + (index.val + 10) = nonmintAddress index.val := by
        rw [nonmintAddress,if_neg low,if_pos middle]; omega
      rwa [address] at zero
    · have zero := full_candidate_nonmint_boolean_zero statement witness nonmint (index.val - 14)
        (by omega) (by omega)
      have address : 42112 + (index.val - 14) = nonmintAddress index.val := by
        rw [nonmintAddress,if_neg low,if_neg middle]; omega
      rwa [address] at zero

noncomputable section
theorem full_candidate_nonmint_attempt_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 40) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (nonmintAttempt index.val) = 0 := by
  have mint := (live_typed_direction_coefficients statement witness valid).1
  simp only [actualCsrResidual,nonmintAttempt,attempt,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,live_coefficient_308,
    (actual_csr_zero_one _).1,add_zero,sub_zero,mint]
  by_cases direction : statement.stablecoin.direction = .mint
  · simp only [typedMint,if_pos direction,sub_self,zero_mul]
  · rw [full_candidate_nonmint_address_zero statement witness direction index,Nat.cast_zero,mul_zero]

theorem full_candidate_actual_nonmint40_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 40) :
    (exactCsrAttempts[20335 + index.val]?).map
      (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)) = some 0 := by
  simp only [nonmint_exact_lookup,Option.map_some,full_candidate_nonmint_attempt_zero statement witness valid index]
end
end HegemonCrypto.SmallWood.V8Smz9SourceNonmintCsr40
